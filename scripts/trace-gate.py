#!/usr/bin/env python3
"""Who sent this line, decided by the kernel and the process tree.

On macOS a pane's token is a secret, because no process can read another's
environment there (measured). On Linux it is not: `/proc/<pid>/environ` is
readable by every process of the same uid, and every pane runs as the same
uid — so a pane can take a peer's token from /proc and write lines to the
collector as that peer, and the collector would call them verified.

This gate sits in front of the collector on Linux and does not use a secret
from the sender at all. A Unix socket tells its server the connecting
process's pid through SO_PEERCRED; the kernel fills it in, nothing in the
pane chooses it. From that pid the gate walks parents upward through /proc
until it finds the *topmost* process that carries a SWARM_TRACE_TOKEN in its
environment — the pane's own shell, spawned by Herdr with the token the
kickoff minted. A pane can put anything in its own environment and its
children's; it cannot reach up and change its parent's. So the topmost
carrier is the pane, whoever connected.

The gate then forwards the line to the collector with *that* pane's token,
stripping whatever the sender supplied. The collector is unchanged: it still
attributes by token, and `claimed_agent` still records a body that names
someone else. What changed is where the token comes from.

    trace-gate.py <sandbox> --tokens [--collector PATH] [--socket PATH] [--quiet]

The token map arrives on stdin, like the collector's, as `{"tokens": {...},
"gate": "<key>"}`. The key is the gate's own secret, shared with the collector
and with nothing else: every line the gate forwards carries it, and the
collector counts a token only on a line that does. So a pane that connects to
the collector directly with a token it read from /proc gets `agent_unverified`
— the key is in no environment and on no disk, and the only process that
puts it on a line is this one. A line whose sender has no pane in its
ancestry is forwarded without a token and comes out `agent_unverified` too,
which is the honest answer.

Orphans: a pane could fork a child that carries a peer's token, let the
parent exit, and have the child reparented above the pane — with no pane in
its ancestry the walk would find only the peer's token. The pane's root is a
child subreaper (landlock.py --subreaper, set by fsguard on Linux), so an
orphan inside the pane is reparented to the pane's root, which carries the
pane's token. Under a pid namespace the namespace's init does the same.
"""
import json
import os
import socket
import struct
import sys
import threading

GATE_SOCKET_REL = "traces/.collector-gate.sock"
COLLECTOR_SOCKET_REL = "traces/.collector.sock"
MAX_LINE = 64_000_000
IDLE_S = 30


def environ_of(pid):
    try:
        with open(f"/proc/{pid}/environ", "rb") as f:
            data = f.read()
    except OSError:
        return {}
    out = {}
    for item in data.split(b"\0"):
        if b"=" in item:
            k, v = item.split(b"=", 1)
            out[k.decode(errors="replace")] = v.decode(errors="replace")
    return out


def parent_of(pid):
    try:
        with open(f"/proc/{pid}/status", "r") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except (OSError, ValueError):
        pass
    return 0


def pane_token(pid, tokens):
    """The token of the topmost ancestor that carries one this run minted."""
    found = None
    seen = 0
    while pid > 1 and seen < 256:
        t = environ_of(pid).get("SWARM_TRACE_TOKEN")
        if t and t in tokens:
            found = t
        pid = parent_of(pid)
        seen += 1
    return found


def peer_pid(conn):
    # struct ucred: pid_t, uid_t, gid_t
    creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, _uid, _gid = struct.unpack("3i", creds)
    return pid


def forward(collector, line):
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(5)
    try:
        s.connect(collector)
        s.sendall(line.encode("utf-8") + b"\n")
        answer = b""
        while not answer.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            answer += chunk
        return answer.decode(errors="replace").strip() or '{"ok":false}'
    except OSError as err:
        return json.dumps({"ok": False, "error": str(err)})
    finally:
        s.close()


def serve(conn, tokens, key, collector, quiet):
    conn.settimeout(IDLE_S)
    try:
        pid = peer_pid(conn)
        token = pane_token(pid, tokens)
        buf = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_LINE:
                break
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                if not raw.strip():
                    continue
                try:
                    record = json.loads(raw)
                except ValueError:
                    conn.sendall(b'{"ok":false,"error":"not json"}\n')
                    continue
                if not isinstance(record, dict):
                    conn.sendall(b'{"ok":false,"error":"not an object"}\n')
                    continue
                record.pop("token", None)
                record.pop("gate", None)
                if token:
                    record["token"] = token
                if key:
                    record["gate"] = key
                answer = forward(collector, json.dumps(record))
                if not quiet:
                    print(f"trace-gate: pid {pid} -> {tokens.get(token, 'unverified')}: {answer}", flush=True)
                conn.sendall(answer.encode() + b"\n")
    except (OSError, socket.timeout):
        pass
    finally:
        conn.close()


def main():
    args = sys.argv[1:]
    if not args:
        print("trace-gate: usage: trace-gate.py <sandbox> --tokens [--collector PATH] [--socket PATH]", file=sys.stderr)
        return 2
    sandbox = os.path.realpath(args[0])
    collector = os.path.join(sandbox, COLLECTOR_SOCKET_REL)
    gate = os.path.join(sandbox, GATE_SOCKET_REL)
    quiet = "--quiet" in args
    if "--collector" in args:
        collector = args[args.index("--collector") + 1]
    if "--socket" in args:
        gate = args[args.index("--socket") + 1]
    tokens = {}
    key = ""
    if "--tokens" in args:
        try:
            parsed = json.loads(sys.stdin.read().strip() or "{}")
            if not isinstance(parsed, dict) or not isinstance(parsed.get("tokens"), dict):
                raise ValueError("no tokens object")
            tokens = {k: v for k, v in parsed["tokens"].items() if isinstance(v, str)}
            key = parsed.get("gate") if isinstance(parsed.get("gate"), str) else ""
        except (ValueError, AttributeError) as err:
            print(f"trace-gate: --tokens expected one line of JSON on stdin, {{tokens, gate}} ({err})", file=sys.stderr)
    # One line for the log, whatever --quiet says: a gate without the key
    # forwards lines the collector cannot count.
    print(f"trace-gate: up, {len(tokens)} token(s), key: {'yes' if key else 'no'}", flush=True)
    if not os.path.isdir(os.path.dirname(gate)):
        os.makedirs(os.path.dirname(gate), exist_ok=True)
    try:
        os.unlink(gate)
    except FileNotFoundError:
        pass
    srv = socket.socket(socket.AF_UNIX)
    # The same ~104-byte sun_path limit the collector works around.
    cwd = os.getcwd()
    os.chdir(os.path.dirname(gate))
    srv.bind(os.path.basename(gate))
    os.chdir(cwd)
    os.chmod(gate, 0o600)
    srv.listen(64)

    # A gate whose run has been deleted has nothing left to guard.
    def watchdog():
        import time
        while True:
            time.sleep(60)
            if not os.path.isdir(sandbox):
                os._exit(0)
    threading.Thread(target=watchdog, daemon=True).start()

    if not quiet:
        print(f"trace-gate: {gate} -> {collector}", flush=True)
    try:
        while True:
            conn, _ = srv.accept()
            threading.Thread(target=serve, args=(conn, tokens, key, collector, quiet), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        try:
            os.unlink(gate)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
