#!/usr/bin/env python3
"""Runs inside one of several VMs that mount the same host directory
read-write, as agents' VMs would share a run's sandbox. Each mode exercises
one filesystem guarantee the swarm protocol leans on.

  guest-shared.py MODE DIR NAME [N]

  excl     N rounds of: create lock with O_CREAT|O_EXCL, read-increment-write
           a counter, unlink the lock. Lost increments = no mutual exclusion.
  flock    the same with fcntl.flock on a shared lock file.
  append   N lines appended with O_APPEND, each long and self-checking.
  rename   writer: N times write a temp file and rename it over `current`;
           reader: read `current` N times, count torn or unparsable reads.
  see      write a marker, then poll until every peer's marker is visible;
           print how long that took.
  inotify  watch DIR with inotify for 20 s and print what arrives (changes
           made by other VMs or the host).
"""
import ctypes
import errno
import fcntl
import json
import os
import struct
import sys
import time

mode, root, name = sys.argv[1], sys.argv[2], sys.argv[3]
n = int(sys.argv[4]) if len(sys.argv) > 4 else 200


def counter_bump():
    path = os.path.join(root, "counter")
    with open(path, "r+") as f:
        v = int(f.read().strip() or 0)
        f.seek(0)
        f.write(str(v + 1))
        f.truncate()
        f.flush()
        os.fsync(f.fileno())


if mode == "excl":
    lock = os.path.join(root, "lock")
    spins = 0
    for _ in range(n):
        while True:
            try:
                fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                spins += 1
                time.sleep(0.001)
        os.write(fd, name.encode())
        os.close(fd)
        counter_bump()
        os.unlink(lock)
    print(json.dumps({"mode": mode, "name": name, "rounds": n, "spins": spins}))

elif mode == "flock":
    spins = 0
    with open(os.path.join(root, "flock"), "a+") as lf:
        for _ in range(n):
            fcntl.flock(lf, fcntl.LOCK_EX)
            counter_bump()
            fcntl.flock(lf, fcntl.LOCK_UN)
    print(json.dumps({"mode": mode, "name": name, "rounds": n}))

elif mode == "append":
    path = os.path.join(root, "appended.log")
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o644)
    for i in range(n):
        body = f"{name}:{i}:" + "x" * 3000
        line = f"{body}|{len(body)}\n".encode()
        os.write(fd, line)
    os.close(fd)
    print(json.dumps({"mode": mode, "name": name, "lines": n}))

elif mode == "rename":
    cur = os.path.join(root, "current")
    if name.startswith("writer"):
        for i in range(n):
            tmp = os.path.join(root, f".tmp-{name}-{i}")
            payload = json.dumps({"i": i, "by": name, "pad": "y" * 20000})
            with open(tmp, "w") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.rename(tmp, cur)
        print(json.dumps({"mode": mode, "name": name, "writes": n}))
    else:
        torn = missing = ok = 0
        for _ in range(n * 5):
            try:
                with open(cur) as f:
                    json.loads(f.read())
                ok += 1
            except FileNotFoundError:
                missing += 1
            except ValueError:
                torn += 1
            time.sleep(0.001)
        print(json.dumps({"mode": mode, "name": name, "ok": ok, "torn": torn, "missing": missing}))

elif mode == "see":
    peers = sys.argv[5].split(",")
    open(os.path.join(root, f"seen-{name}"), "w").write(str(time.time()))
    start = time.time()
    while not all(os.path.exists(os.path.join(root, f"seen-{p}")) for p in peers):
        if time.time() - start > 30:
            break
        time.sleep(0.005)
    missing = [p for p in peers if not os.path.exists(os.path.join(root, f"seen-{p}"))]
    print(json.dumps({"mode": mode, "name": name, "waited_s": round(time.time() - start, 3), "missing": missing}))

elif mode == "inotify":
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    fd = libc.inotify_init1(os.O_NONBLOCK)
    wd = libc.inotify_add_watch(fd, root.encode(), 0x00000002 | 0x00000100 | 0x00000008 | 0x00000080)
    events = []
    end = time.time() + 20
    while time.time() < end:
        try:
            data = os.read(fd, 4096)
        except BlockingIOError:
            time.sleep(0.05)
            continue
        off = 0
        while off < len(data):
            _, mask, _, ln = struct.unpack_from("iIII", data, off)
            fname = data[off + 16: off + 16 + ln].rstrip(b"\0").decode()
            events.append(f"{hex(mask)}:{fname}")
            off += 16 + ln
    print(json.dumps({"mode": mode, "name": name, "watch": wd, "events": events[:20], "count": len(events)}))
