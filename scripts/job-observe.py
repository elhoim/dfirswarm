#!/usr/bin/env python3
"""
EXPERIMENTAL and UNTESTED in a worker VM: what a job opened, observed with
fanotify from inside its worker (ADR 0010, "A job sees what it declared").
Off unless the hub runs with SWARM_JOB_OBSERVE=fanotify-experimental. Never
evidence of what a job read until the acceptance tests in
tests/job-observe-vm.test.ts pass on the host's own kernel and virtio-fs.

    python3 job-observe.py <out-dir> <mount>...

Run as root in the worker, before the job's own command, which then runs as
an unprivileged user. It marks each mount (FAN_MARK_MOUNT: a mount inside
another needs its own mark), and writes one JSON line per event to
<out-dir>/events.jsonl: the path the kernel's descriptor names, the pid,
what happened (open, access, exec, close), and a heartbeat each second while
nothing happens. Each line carries `prev` (the mac of the line before) and
`mac` (HMAC-SHA256 over the line without it, keyed by 32 random bytes the
collector writes to <out-dir>/key, root-only): a line the job wrote, or one
edited or dropped, does not verify. A queue overflow is a line of its own. On
SIGTERM it drains what is queued and writes `end` with its counts; a log
without `end` is a collector that died. What cannot be marked, or a kernel
without fanotify, is said in `start`, and the host reads the log as unknown.

What this cannot see, said here so nobody reads more into it: a read through
mmap raises no access event (the open is seen); a read of a file opened
before the marks were placed; anything outside the marked mounts. The host
(scripts/job-observe.ts) turns this into complete, partial or unknown, never
complete unless every check holds.
"""
import ctypes
import hashlib
import hmac
import json
import os
import select
import signal
import struct
import sys
import time

FAN_CLOEXEC = 0x1
FAN_NONBLOCK = 0x2
FAN_CLASS_NOTIF = 0x0
FAN_MARK_ADD = 0x1
FAN_MARK_MOUNT = 0x10
FAN_ACCESS = 0x1
FAN_CLOSE_NOWRITE = 0x10
FAN_OPEN = 0x20
FAN_OPEN_EXEC = 0x1000
FAN_Q_OVERFLOW = 0x4000
FAN_ONDIR = 0x40000000
FAN_NOFD = -1
AT_FDCWD = -100
MASK = FAN_ACCESS | FAN_OPEN | FAN_OPEN_EXEC | FAN_CLOSE_NOWRITE | FAN_ONDIR
# struct fanotify_event_metadata: event_len, vers, reserved, metadata_len, mask, fd, pid
META = struct.Struct("=IBBHQii")
KINDS = [(FAN_OPEN, "open"), (FAN_ACCESS, "access"), (FAN_OPEN_EXEC, "exec"), (FAN_CLOSE_NOWRITE, "close")]


class Log:
    def __init__(self, out):
        os.makedirs(out, mode=0o700, exist_ok=True)
        os.chmod(out, 0o700)
        self.key = os.urandom(32)
        fd = os.open(os.path.join(out, "key"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, self.key.hex().encode())
        os.close(fd)
        self.fh = open(os.path.join(out, "events.jsonl"), "a", encoding="utf-8")
        os.chmod(os.path.join(out, "events.jsonl"), 0o600)
        self.seq = 0
        self.prev = ""

    def write(self, rec):
        # t in microseconds: a whole number JSON readers keep exactly. The
        # mac is over the same canonical text a reader rebuilds (sorted keys,
        # no spaces, non-ASCII as itself).
        rec = dict(rec, seq=self.seq, t=time.monotonic_ns() // 1000, prev=self.prev)
        body = json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        mac = hmac.new(self.key, body.encode(), hashlib.sha256).hexdigest()
        self.fh.write(json.dumps(dict(rec, mac=mac), sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        self.fh.flush()
        self.seq += 1
        self.prev = mac


def main(argv):
    if len(argv) < 3:
        sys.stderr.write("usage: job-observe.py <out-dir> <mount>...\n")
        return 2
    log = Log(argv[1])
    mounts = argv[2:]
    libc = ctypes.CDLL(None, use_errno=True)
    start = {"kind": "start", "pid": os.getpid(), "uid": os.getuid(), "kernel": os.uname().release, "marks": []}
    init = getattr(libc, "fanotify_init", None)
    mark = getattr(libc, "fanotify_mark", None)
    if init is None or mark is None:
        log.write(dict(start, unsupported="this libc has no fanotify"))
        return 0
    init.restype = ctypes.c_int
    mark.argtypes = [ctypes.c_int, ctypes.c_uint, ctypes.c_uint64, ctypes.c_int, ctypes.c_char_p]
    fan = init(ctypes.c_uint(FAN_CLASS_NOTIF | FAN_CLOEXEC | FAN_NONBLOCK), ctypes.c_uint(os.O_RDONLY | getattr(os, "O_LARGEFILE", 0)))
    if fan < 0:
        e = ctypes.get_errno()
        log.write(dict(start, unsupported="fanotify_init: %s" % os.strerror(e)))
        return 0
    for m in mounts:
        r = mark(fan, FAN_MARK_ADD | FAN_MARK_MOUNT, MASK, AT_FDCWD, os.fsencode(m))
        e = ctypes.get_errno() if r != 0 else 0
        start["marks"].append({"mount": m, "ok": r == 0, **({"error": os.strerror(e)} if r != 0 else {})})
    log.write(start)
    stop = {"now": False}
    signal.signal(signal.SIGTERM, lambda *_: stop.__setitem__("now", True))
    counts = {"events": 0, "overflow": 0, "unnamed": 0}
    me = os.getpid()
    while True:
        ready, _, _ = select.select([fan], [], [], 1.0)
        if not ready:
            if stop["now"]:
                break
            log.write({"kind": "heartbeat"})
            continue
        try:
            buf = os.read(fan, 65536)
        except BlockingIOError:
            continue
        at = 0
        while at + META.size <= len(buf):
            length, _vers, _res, _mlen, mask, fd, pid = META.unpack_from(buf, at)
            at += length or META.size
            if mask & FAN_Q_OVERFLOW:
                counts["overflow"] += 1
                log.write({"kind": "overflow"})
                continue
            if fd == FAN_NOFD or fd < 0:
                counts["unnamed"] += 1
                continue
            try:
                path = os.readlink("/proc/self/fd/%d" % fd)
            except OSError as x:
                path = None
                log.write({"kind": "error", "error": "readlink: %s" % x.strerror})
            finally:
                os.close(fd)
            if pid == me or path is None:
                continue
            counts["events"] += 1
            log.write({"kind": "event", "what": [k for bit, k in KINDS if mask & bit], "path": path, "pid": pid, "dir": bool(mask & FAN_ONDIR)})
    log.write(dict({"kind": "end"}, **counts))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
