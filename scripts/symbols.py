#!/usr/bin/env python3
"""The operator's symbol store: what an image build converts into symbol
tables, fetched by the operator, on the host, as a visible act.

    scripts/swarm.sh symbols fetch --accept-terms --accepted-by NAME [--from DIR] [--name TEXT]... [--packs DIR] [--store DIR]
    scripts/swarm.sh symbols list  [--packs DIR] [--store DIR] [--json]

A pack lists the exact symbol files its images carry (a data entry with
`acquire: "operator"`, usually expanded from a list file such as
packs/memory-forensics/requires/symbols.windows.json): each with its url, its
sha256 and its size. `fetch` puts each into the store,

    $DFIRSWARM_HOME/symbols/blobs/sha256/<sha256>     (read-only, by content)
    $DFIRSWARM_HOME/symbols/manifest.json             (each file: its name, size, and the acceptance)
    $DFIRSWARM_HOME/symbols/fetched.jsonl             (one line per file put there)

either from a directory the operator already holds (`--from DIR`: every
regular file of the pinned size under it is hashed, and the one with the
pinned sha256 is copied; nothing else is read) or from its url: HTTPS on every
hop, at most the entry's `fetch.max_redirects` redirects and only to its
`fetch.redirect_hosts`, no more bytes than pinned, within its
`fetch.timeout_seconds`. Bytes that are not the pinned ones are never kept.

The files are their supplier's, under its terms (the entry's `terms`). A fetch
is the operator's acceptance of them, so it is refused without
`--accept-terms` and `--accepted-by NAME`; nothing stands in for the name.
The acceptance (who, the terms' name and URL, when, the file's sha256, and
how: whether a terminal was on both ends, the account, the host, the
command) is written into the store's manifest.json for every file the fetch
puts there or finds there, every earlier acceptance kept beside it, and each
is a line of fetched.jsonl. A build takes an unattended acceptance (a
process, not a person at a terminal) only when told to. `images/recipe.py build --symbols-from`
(by default this store) then hands the files to the build with their
acceptance, which the image records beside what it made of them; a file with
no recorded acceptance is not built in.

The store must not be in a folder a sync client copies elsewhere (Dropbox,
iCloud Drive, OneDrive, a CloudStorage provider): what it holds is not ours to
distribute, and a synced folder distributes it.

`list` says, for every such entry, whether the store holds it.

Exit: 0 every entry asked for is held, 1 one is not, 2 a refusal or a usage error.
"""
import argparse
import getpass
import hashlib
import json
import os
import shutil
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "images"))
import install  # noqa: E402  (images/install.py: the bounded download, the redirect rule)
import recipe  # noqa: E402  (images/recipe.py: a pack's data entries, its list files expanded)

# Where a sync client copies what is put there (images/install.py keeps the list).
synced = install.synced


def store_dir(given: str | None) -> Path:
    if given:
        return Path(given)
    home = os.environ.get("DFIRSWARM_HOME") or str(Path.home() / ".dfirswarm")
    return Path(home) / "symbols"


def operator_entries(packs: Path) -> list:
    """Every data entry a pack under packs says the operator acquires."""
    out = []
    for pj in sorted(packs.glob("*/pack.json")):
        pack = pj.parent
        host = pack / "requires" / "host.json"
        if not host.is_file():
            continue
        for b in json.loads(host.read_text()).get("binaries", []):
            for d in recipe.data_entries(pack, (b.get("install") or {}).get("data")):
                if d.get("acquire") == "operator":
                    out.append({**d, "pack": pack.name, "program": b.get("name")})
    return out


def wanted(entries: list, names: list) -> list:
    if not names:
        return entries
    return [d for d in entries if any(n.lower() in f"{d.get('name', '')} {d.get('version', '')}".lower() for n in names)]


def blob(store: Path, sha: str) -> Path:
    return store / "blobs" / "sha256" / sha


def held(store: Path, d: dict) -> bool:
    p = blob(store, pinned_sha(d))
    return p.is_file() and install.sha256_file(p) == pinned_sha(d)


def pinned_sha(d: dict) -> str:
    return str(d.get("sha256", "")).removeprefix("sha256:").lower()


def find_in(directory: Path, d: dict) -> Path | None:
    """The file under directory with the pinned size and sha256: only files of
    that size are hashed, links are not followed."""
    size, sha = d.get("bytes"), pinned_sha(d)
    for dirpath, dirs, files in os.walk(directory, followlinks=False):
        dirs.sort()
        for f in sorted(files):
            p = Path(dirpath) / f
            try:
                st = p.lstat()
            except OSError:
                continue
            if not p.is_file() or p.is_symlink() or (isinstance(size, int) and st.st_size != size):
                continue
            if install.sha256_file(p) == sha:
                return p
    return None


def tls_context() -> ssl.SSLContext:
    """A verifying context; a Python with no CA bundle of its own (python.org's
    on macOS) is given the system's, never no verification."""
    ctx = ssl.create_default_context()
    paths = ssl.get_default_verify_paths()
    if not (paths.cafile and os.path.exists(paths.cafile)) and not (paths.capath and os.path.isdir(paths.capath) and os.listdir(paths.capath)):
        for cafile in ("/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"):
            if os.path.exists(cafile):
                ctx.load_verify_locations(cafile)
                break
    return ctx


def download(d: dict, dest: Path) -> tuple:
    """(why it failed or None, the host it came from)."""
    fetch = d.get("fetch") if isinstance(d.get("fetch"), dict) else {}
    hosts = [str(h) for h in fetch.get("redirect_hosts") or []]
    handler = install.HttpsRedirects(hosts)
    handler.max_redirections = int(fetch.get("max_redirects", 2))
    old = install.FETCH_SECONDS
    install.FETCH_SECONDS = int(fetch.get("timeout_seconds", 600))
    try:
        hexd, got, _ = install.fetch_once(d["url"], dest, d.get("bytes"), opener_handlers=[handler, install.urllib.request.HTTPSHandler(context=tls_context())])
    except (OSError, install.http.client.HTTPException) as e:
        dest.unlink(missing_ok=True)
        return f"download failed: {e}", None
    finally:
        install.FETCH_SECONDS = old
    if hexd != pinned_sha(d) or (isinstance(d.get("bytes"), int) and got != d["bytes"]):
        dest.unlink(missing_ok=True)
        return f"{got} bytes with sha256 {hexd}, not the pinned {d.get('bytes')} bytes with sha256 {pinned_sha(d)}", None
    return None, handler.last_host or install.urllib.parse.urlparse(d["url"]).hostname


def put(store: Path, src: Path, d: dict) -> Path:
    """src into the store under its sha256, read-only; src itself is left as it was."""
    dest = blob(store, pinned_sha(d))
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_name(dest.name + f".part-{os.getpid()}")
    shutil.copyfile(src, tmp)
    if install.sha256_file(tmp) != pinned_sha(d):
        tmp.unlink(missing_ok=True)
        raise OSError(f"{src} changed while it was copied")
    tmp.chmod(0o444)
    os.replace(tmp, dest)
    return dest


def manifest(store: Path) -> dict:
    try:
        m = json.loads((store / "manifest.json").read_text())
        return m if isinstance(m, dict) and isinstance(m.get("files"), dict) else {"version": 1, "files": {}}
    except (OSError, ValueError):
        return {"version": 1, "files": {}}


def acceptor_context(argv: list) -> dict:
    """What tells a person at a terminal from a process: whether both ends are
    a terminal, the account, the host, how it was called, and the command."""
    return {"attended": bool(sys.stdin.isatty() and sys.stdout.isatty()),
            "os_user": getpass.getuser(), "host": socket.gethostname(),
            "via": os.environ.get("SWARM_OPERATOR_VIA", "cli"), "argv": ["swarm.sh", "symbols", *argv]}


def record_acceptance(store: Path, d: dict, accepted_by: str, context: dict) -> dict:
    """Write who accepted the terms of this file, when, for which bytes, and
    how (attended or not, account, host, command) into manifest.json: the
    current acceptance, and every earlier one kept beside it. Journaled too."""
    m = manifest(store)
    terms = d.get("terms") or {}
    acceptance = {"accepted_by": accepted_by, "accepted_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "terms": {"supplier": terms.get("supplier"), "name": terms.get("name"), "url": terms.get("url")},
                  "sha256": pinned_sha(d), "how": "swarm.sh symbols fetch --accept-terms", **context}
    prev = m["files"].get(pinned_sha(d)) or {}
    history = list(prev.get("acceptances") or ([prev["acceptance"]] if prev.get("acceptance") else []))
    m["files"][pinned_sha(d)] = {"name": d["name"], "pack": d.get("pack"), "bytes": d.get("bytes"), "url": d.get("url"),
                                 "acceptance": acceptance, "acceptances": history + [acceptance]}
    tmp = store / f".manifest-{os.getpid()}.json"
    tmp.write_text(json.dumps(m, indent=1, sort_keys=True) + "\n")
    os.replace(tmp, store / "manifest.json")
    journal(store, {"how": "accept", "name": d["name"], "sha256": pinned_sha(d), "acceptance": acceptance})
    return acceptance


def journal(store: Path, line: dict) -> None:
    with open(store / "fetched.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps({"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), **line}, sort_keys=True) + "\n")


def cmd_list(a) -> int:
    store = store_dir(a.store)
    files = manifest(store)["files"]
    rows = [{"name": d["name"], "pack": d["pack"], "url": d["url"], "sha256": pinned_sha(d), "bytes": d.get("bytes"),
             "held": held(store, d), "acceptance": (files.get(pinned_sha(d)) or {}).get("acceptance")} for d in operator_entries(a.packs)]
    if a.json:
        print(json.dumps({"store": str(store), "entries": rows}, indent=1))
    else:
        print(f"symbol store: {store}")
        for r in rows:
            acc = r["acceptance"]
            print(f"  {'held   ' if r['held'] else 'missing'}  {r['name']}  ({r['pack']}; {r['bytes']} bytes, sha256 {r['sha256']}; "
                  + (f"terms accepted by {acc.get('accepted_by')} at {acc.get('accepted_at')})" if acc else "no acceptance recorded)"))
    return 0 if all(r["held"] for r in rows) else 1


def cmd_fetch(a, argv: list) -> int:
    store = store_dir(a.store)
    mark = synced(store) or synced(store.parent)
    if mark:
        print(f"symbols: refused: the store {store} is in a synced folder ({mark}); what it holds must stay on this machine. "
              "Set DFIRSWARM_HOME (or --store) to a directory no sync client copies.", file=sys.stderr)
        return 2
    entries = wanted(operator_entries(a.packs), a.name or [])
    if not entries:
        print("symbols: no pack lists a file for the operator to fetch" + (f" matching {', '.join(a.name)}" if a.name else ""), file=sys.stderr)
        return 2
    if a.from_dir and not a.from_dir.is_dir():
        print(f"symbols: --from {a.from_dir} is not a directory", file=sys.stderr)
        return 2
    # Accepting the supplier's terms is the operator's act, said and named
    # before anything is fetched or stored.
    terms_said = {json.dumps(d.get("terms") or {}, sort_keys=True) for d in entries}
    accepted_by = (a.accepted_by or "").strip()
    if not a.accept_terms or not accepted_by:
        for t in sorted(terms_said):
            terms = json.loads(t)
            print(f"These files are {terms.get('supplier', 'their publisher')}'s, under {terms.get('name', 'its terms')} "
                  f"({terms.get('url', 'no terms URL given')}).", file=sys.stderr)
        print("symbols: refused: fetching or storing them is your acceptance of those terms, recorded in the store and in every "
              "image built from it. Run again with --accept-terms and --accepted-by NAME"
              + (" (whose name: nothing stands in for it)" if a.accept_terms and not accepted_by else "") + ".", file=sys.stderr)
        return 2
    store.mkdir(parents=True, exist_ok=True)
    os.chmod(store, 0o700)
    context = acceptor_context(argv)
    if not context["attended"]:
        print(f"symbols: no terminal on both ends: the acceptance by {accepted_by} is recorded as unattended (a process, not a "
              "person at a terminal); a build takes it only with --allow-unattended-acceptance.", file=sys.stderr)
    todo = [d for d in entries if not held(store, d)]
    for t in sorted(terms_said):
        terms = json.loads(t)
        print(f"{accepted_by} accepts {terms.get('name', 'its terms')} ({terms.get('url', 'no terms URL given')}) for the "
              f"{terms.get('supplier', 'publisher')} files below. They stay on this machine; the images built from them are not "
              "for redistribution.")
    for d in entries:
        if d not in todo:
            record_acceptance(store, d, accepted_by, context)
            print(f"held     {d['name']}  (sha256 {pinned_sha(d)}; acceptance recorded)")
    missing = 0
    for d in todo:
        if a.from_dir:
            src = find_in(a.from_dir, d)
            if not src:
                print(f"missing  {d['name']}  (no file of {d.get('bytes')} bytes with sha256 {pinned_sha(d)} under {a.from_dir})")
                missing += 1
                continue
            dest = put(store, src, d)
            acc = record_acceptance(store, d, accepted_by, context)
            journal(store, {"name": d["name"], "pack": d["pack"], "sha256": pinned_sha(d), "bytes": dest.stat().st_size,
                            "how": "from", "from": str(src), "url": d["url"], "acceptance": acc})
            print(f"stored   {d['name']}  from {src}")
            continue
        tmp = store / f".download-{os.getpid()}"
        start = time.monotonic()
        why, host = download(d, tmp)
        if why:
            print(f"missing  {d['name']}  ({why})")
            missing += 1
            continue
        dest = put(store, tmp, d)
        tmp.unlink(missing_ok=True)
        acc = record_acceptance(store, d, accepted_by, context)
        journal(store, {"name": d["name"], "pack": d["pack"], "sha256": pinned_sha(d), "bytes": dest.stat().st_size,
                        "how": "download", "url": d["url"], "served_by": host, "seconds": round(time.monotonic() - start, 1),
                        "acceptance": acc})
        print(f"stored   {d['name']}  downloaded ({dest.stat().st_size} bytes, served by {host})")
    print(f"symbol store: {store}: {len(entries) - missing} of {len(entries)} held")
    return 1 if missing else 0


def main(argv: list) -> int:
    ap = argparse.ArgumentParser(prog="swarm.sh symbols")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("fetch", "list"):
        s = sub.add_parser(name)
        s.add_argument("--packs", type=Path, default=ROOT / "packs", help="the packs whose lists are read (default this checkout's)")
        s.add_argument("--store", help="the store (default $DFIRSWARM_HOME/symbols)")
        if name == "fetch":
            s.add_argument("--from", dest="from_dir", type=Path, help="a directory that already holds the files: nothing is downloaded")
            s.add_argument("--name", action="append", help="only the entries whose name or version holds TEXT (a GUID); repeatable")
            s.add_argument("--accept-terms", action="store_true", help="accept the supplier's terms for these files (required)")
            s.add_argument("--accepted-by", help="who accepts them, by name (required with --accept-terms; nothing stands in for it)")
        else:
            s.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    return cmd_fetch(a, argv) if a.cmd == "fetch" else cmd_list(a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
