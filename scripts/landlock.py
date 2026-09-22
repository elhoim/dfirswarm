#!/usr/bin/env python3
"""A write allowlist from the kernel, with no namespace underneath it.

Landlock is a Linux security module (5.13 and later) that lets an unprivileged
process restrict itself: it builds a ruleset of what may be done beneath which
directories, applies it, and from then on every descendant is bound by it and
nothing can loosen it. It is the closest thing Linux has to the seatbelt
profile the macOS panes run under, and it is the one guard that survives the
places user namespaces do not reach — Docker's default seccomp profile,
Ubuntu's AppArmor restriction on unprivileged namespaces, a hardened host with
`user.max_user_namespaces=0`. Measured on a 7.0 kernel, ABI 8, from this file
with nothing installed: writes outside the sandbox refused, inside allowed,
the evidence readable, `pip install --user` outside the run refused.

    landlock.py [--rw DIR]... [--ro DIR]... [--noexec DIR]... [--no-read DIR]...
                [--net-port N]... [--subreaper] [--dry-run] -- command...

--subreaper makes the command a child subreaper (prctl PR_SET_CHILD_SUBREAPER):
a descendant whose parent exits is reparented to the command rather than to
init, so the whole pane stays one process tree under one root. The trace gate
attributes a line by walking that tree, and an orphan that climbed out of it
would be attributed by whatever token it chose to carry. Orphans the root
never waits for stay zombies until the pane ends; that costs a pid each.

The vocabulary is fsguard's, and the semantics are as close as the mechanism
allows. Landlock grants; it does not subtract. A rule beneath a directory
covers everything beneath it, so two of fsguard's shapes need a different
construction here:

  --no-read DIR   nothing beneath DIR may be opened. Landlock cannot say
                  "everything except DIR", so this grants read to every
                  sibling of every component of DIR's path, and READ_DIR only
                  (never READ_FILE) to its ancestors. Listing a directory still
                  works everywhere; opening a file under DIR does not.
  --noexec DIR    Landlock cannot withhold execute beneath a directory that a
                  wider rule grants it to. When DIR lies under a --rw
                  directory, that --rw directory is granted everything except
                  EXECUTE: files there may be written and read, and run only
                  through an interpreter. That is stricter than asked, and
                  it is the honest version.

Only what the harness itself needs, in the standard library. Exit 3 when
Landlock is not there, so a caller can fall back and say so.
"""
import ctypes
import os
import sys

SYS_CREATE_RULESET, SYS_ADD_RULE, SYS_RESTRICT_SELF = 444, 445, 446
PR_SET_NO_NEW_PRIVS = 38
PR_SET_CHILD_SUBREAPER = 36
RULE_PATH_BENEATH, RULE_NET_PORT = 1, 2

FS_EXECUTE, FS_WRITE_FILE, FS_READ_FILE, FS_READ_DIR = 0x1, 0x2, 0x4, 0x8
FS_ALL_V1 = 0x1FFF
FS_REFER, FS_TRUNCATE, FS_IOCTL_DEV = 0x2000, 0x4000, 0x8000
NET_CONNECT_TCP = 0x2
READ = FS_READ_FILE | FS_READ_DIR | FS_EXECUTE
# A rule on a regular file may only carry the rights that mean something for
# a file; the kernel answers EINVAL to a directory right on a file, and the
# sibling walk for --no-read reaches files as well as directories.
FILE_ONLY = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV

libc = ctypes.CDLL(None, use_errno=True)


class RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64), ("handled_access_net", ctypes.c_uint64)]


class PathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


class NetPort(ctypes.Structure):
    _fields_ = [("allowed_access", ctypes.c_uint64), ("port", ctypes.c_uint64)]


def abi_version():
    v = libc.syscall(SYS_CREATE_RULESET, None, 0, 1)
    return v if v > 0 else 0


def parse(argv):
    opts = {"rw": [], "ro": [], "noexec": [], "no_read": [], "ports": [], "dry": False, "subreaper": False}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            return opts, argv[i + 1 :]
        if a in ("--rw", "--ro", "--noexec", "--no-read", "--net-port"):
            if i + 1 >= len(argv):
                die(f"{a} needs a value")
            key = {"--rw": "rw", "--ro": "ro", "--noexec": "noexec", "--no-read": "no_read", "--net-port": "ports"}[a]
            opts[key].append(argv[i + 1])
            i += 2
            continue
        if a == "--dry-run":
            opts["dry"] = True
            i += 1
            continue
        if a == "--subreaper":
            opts["subreaper"] = True
            i += 1
            continue
        die(f"unknown option {a}")
    return opts, []


def die(msg, code=2):
    print(f"landlock: {msg}", file=sys.stderr)
    sys.exit(code)


def canonical(path):
    # The rule is on the inode the path resolves to now; a symlinked component
    # would otherwise grant the link and not the target.
    return os.path.realpath(path)


def plan(opts, abi):
    """Every rule as (path, access), in the order they will be added.

    Landlock grants beneath a directory and never subtracts, so a path that
    must be *less* than its surroundings — read-only evidence inside the
    writable sandbox, a denied directory inside a readable tree — is "carved":
    every sibling along its path gets the surrounding rights, its ancestors
    get READ_DIR only (a listing, never an open, never a create), and the
    carved path gets its own smaller grant. Files that sit beside a carved
    path get file rights, so `team.json` in the sandbox root is still
    writable in place; nothing new can be created in a carved ancestor, which
    is why the kickoff creates every directory a run needs before the panes
    start.
    """
    handled = FS_ALL_V1
    if abi >= 2:
        handled |= FS_REFER
    if abi >= 3:
        handled |= FS_TRUNCATE
    if abi >= 5:
        handled |= FS_IOCTL_DEV
    rw = [canonical(p) for p in opts["rw"]]
    ro = [canonical(p) for p in opts["ro"]]
    noexec = [canonical(p) for p in opts["noexec"]]
    denied = [canonical(p) for p in opts["no_read"]]

    def rw_rights(path):
        access = handled
        if any(n == path or n.startswith(path + "/") for n in noexec):
            access &= ~FS_EXECUTE
        return access

    # Regions: what a path may do by default, from the innermost enclosing
    # grant. Without any --rw the whole tree is writable (fsguard's --ro alone
    # means "this, read-only; the rest as it was"); with --rw the tree is
    # read-only and the --rw paths are writable.
    def region_rights(path):
        best = None
        for r in rw:
            if path == r or path.startswith(r + "/"):
                if best is None or len(r) > len(best):
                    best = r
        if best is not None:
            return rw_rights(best)
        return handled if not rw else READ

    carved = {}
    for p in ro:
        carved[p] = READ
    for p in denied:
        carved[p] = 0
    # A carve beneath a carve keeps the smaller grant.
    ancestors = set()
    blocked = set(carved)
    for c in carved:
        parts = c.strip("/").split("/")
        for depth in range(len(parts)):
            ancestors.add("/" + "/".join(parts[:depth]) if depth else "/")
    rules = []
    if not carved:
        rules.append(("/", handled if not rw else READ))
    else:
        for anc in sorted(ancestors, key=len):
            try:
                entries = os.listdir(anc)
            except OSError:
                continue
            for e in entries:
                child = os.path.join(anc, e)
                # Resolved, not as written. `blocked` and `ancestors` hold
                # canonical paths, and a *symlink* sibling compared by its own
                # name matches neither — so it was handed the region's rights,
                # and `os.open(..., O_PATH)` follows symlinks, so the rule
                # landed on the target's inode. Landlock unions rights for one
                # inode, so the carve that was supposed to make it read-only
                # was overruled by that grant. Measured on a Linux server with
                # `--inputs-bind`, where `inputs/` is a link to the evidence:
                # the panes could write the evidence directory, and their own
                # probe said "none" while the kickoff said the guard was on.
                real = canonical(child)
                if real in blocked or real in ancestors:
                    continue
                if not os.path.exists(real):
                    continue
                # The rights come from where the link *points*, too: a link
                # inside the writable run that points outside it must not
                # carry the run's write rights out there.
                rules.append((real, region_rights(real)))
            rules.append((anc, FS_READ_DIR))
    for path, access in carved.items():
        if access:
            rules.append((path, access))
    for r in rw:
        if r in ancestors:
            continue  # its children carry the rights; the root itself is READ_DIR
        rules.append((r, rw_rights(r)))
    # /dev needs writes: /dev/null, /dev/tty, /dev/pts, /dev/shm. Device
    # nodes are root's; nothing here can create one.
    if os.path.isdir("/dev") and "/dev" not in ancestors:
        rules.append(("/dev", handled))
    return handled, rules


def main():
    opts, cmd = parse(sys.argv[1:])
    abi = abi_version()
    handled, rules = plan(opts, abi) if abi else (0, [])
    net = NET_CONNECT_TCP if (opts["ports"] and abi >= 4) else 0

    if opts["dry"]:
        print(f"mode: landlock")
        print(f"abi: {abi if abi else 'unavailable'}")
        if not abi:
            return 3
        for p in [canonical(x) for x in opts["rw"]]:
            print(f"writable: {p}")
        for p in [canonical(x) for x in opts["ro"]]:
            print(f"read-only: {p}")
        for p in [canonical(x) for x in opts["noexec"]]:
            print(f"no-exec: {p}  (via: no EXECUTE beneath the enclosing --rw)")
        for p in [canonical(x) for x in opts["no_read"]]:
            print(f"no-read: {p}")
        for p in [canonical(x) for x in opts["ro"]] + [canonical(x) for x in opts["no_read"]]:
            print(f"carved: {os.path.dirname(p)} (listing only; nothing new can be created there)")
        for port in opts["ports"]:
            print(f"tcp-connect-only: {port}" if net else f"tcp-connect-only: {port}  (ignored: ABI {abi} < 4)")
        print(f"rules: {len(rules)}")
        if opts["subreaper"]:
            print("subreaper: yes (orphans are reparented to the command, not to init)")
        return 0

    if not abi:
        die("this kernel has no Landlock (need 5.13 or later, with the LSM enabled)", 3)
    if not cmd:
        die("no command after --")

    attr = RulesetAttr(handled, net)
    size = ctypes.sizeof(attr) if abi >= 4 else 8
    fd = libc.syscall(SYS_CREATE_RULESET, ctypes.byref(attr), size, 0)
    if fd < 0:
        die(f"create_ruleset: {os.strerror(ctypes.get_errno())}", 3)
    for path, access in rules:
        try:
            pfd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        except OSError:
            continue
        if not os.path.isdir(path):
            access &= FILE_ONLY
        access &= handled
        if not access:
            os.close(pfd)
            continue
        rule = PathBeneath(access, pfd)
        r = libc.syscall(SYS_ADD_RULE, fd, RULE_PATH_BENEATH, ctypes.byref(rule), 0)
        os.close(pfd)
        if r < 0:
            die(f"add_rule {path}: {os.strerror(ctypes.get_errno())}", 3)
    if net:
        for port in opts["ports"]:
            rule = NetPort(NET_CONNECT_TCP, int(port))
            if libc.syscall(SYS_ADD_RULE, fd, RULE_NET_PORT, ctypes.byref(rule), 0) < 0:
                die(f"add_rule port {port}: {os.strerror(ctypes.get_errno())}", 3)
    if opts["subreaper"] and libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        die("prctl(CHILD_SUBREAPER) failed", 3)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        die("prctl(NO_NEW_PRIVS) failed", 3)
    if libc.syscall(SYS_RESTRICT_SELF, fd, 0) != 0:
        die(f"restrict_self: {os.strerror(ctypes.get_errno())}", 3)
    os.close(fd)
    os.environ["SWARM_FSGUARD"] = os.environ.get("SWARM_FSGUARD") or "landlock"
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    sys.exit(main())
