#!/usr/bin/env python3
"""Read a Windows registry hive with regipy: a key's values, its subkeys, and a bounded recursive listing.

What it is: a reader, not a decoder. A binary value comes back as hex and nothing more: UserAssist, ShimCache,
BAM, SAM and ShellBag values are not decoded here, and a typed reading of any of them needs a decoder that
knows its layout and its Windows version. Every value carries its registry type and length beside its
value, and nothing is cut (regipy's default trims a value to 256 characters; this reads them whole).

Completeness is said, not assumed. A key or value that cannot be read is named under `problems`, a branch the
walk did not enter (depth or node limit, or an error) under `stopped_branches`, and the answer says whether
the hive is dirty (its two sequence numbers differ: its newest state may be in the .LOG files) and which
transaction logs sit beside it. The logs are NOT replayed here.

SENSITIVE OUTPUT. A value whose name says password, secret, token or credential, the values of the LSA secrets
and cached-logon keys of a SECURITY hive, and the V value of each SAM user (which holds password verifiers) are
registry material that can be a secret. Their text and bytes are never in the answer: the value is replaced by
a marker that holds its length, and `sensitive_values_withheld` lists key, name, type and length. No flag brings
one back; this tool produces no secret and has no capability to recover one.

The key path is read from the hive's root, a leading backslash or not.
"""
import datetime
import json
import os
import re
import sys
import tempfile
from pathlib import Path

from regipy.registry import RegistryHive
from regipy.exceptions import RegistryKeyNotFoundException

PARSER = "regkv/3"
FILETIME_EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
SENSITIVE_NAME = re.compile(r"passw(or)?d|pwd|secret|token|credential|api_?key|private_?key", re.I)
TEXT_OR_BINARY = ("REG_SZ", "REG_EXPAND_SZ", "REG_EXPAND", "REG_MULTI_SZ", "REG_BINARY", "REG_NONE")
INLINE_NODES = 2000
MAX_NODES = 1_000_000

# Lossless paging (the same in every library tool that pages): the page an
# agent reads stays small, and when there are more rows the whole result is
# written as JSON Lines under work/<agent>/tool-output and named.
import hashlib


class LosslessPage:
    def __init__(self, tool: str, key: object, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError("limit must be a positive integer")
        self.tool = re.sub(r"[^A-Za-z0-9_.-]", "_", tool)
        self.limit = limit
        self.page: list[object] = []
        self.total = 0
        self._out = None
        self._tmp: Path | None = None
        digest = hashlib.sha256(
            json.dumps(key, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:16]
        name = f"{self.tool}-{digest}.jsonl"
        job, out = os.environ.get("JOB_ID"), os.environ.get("OUT")
        if job and out:
            # In a job only $OUT is written, and it is sealed as the job's
            # output: the whole result is cited from there.
            self.path = Path(out) / "tool-output" / name
            self.shown = "store/jobs/%s/out/tool-output/%s" % (re.sub(r"[^A-Za-z0-9_.-]", "_", job), name)
        else:
            agent = re.sub(
                r"[^A-Za-z0-9_.-]", "_", os.environ.get("AGENT_ID") or "tool"
            )
            self.path = Path("work") / agent / "tool-output" / name
            self.shown = str(self.path)

    def _write(self, row: object) -> None:
        assert self._out is not None
        self._out.write(json.dumps(row, ensure_ascii=False, default=str))
        self._out.write("\n")

    def add(self, row: object) -> None:
        self.total += 1
        if len(self.page) < self.limit:
            self.page.append(row)
            return
        if self._out is None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, name = tempfile.mkstemp(
                dir=self.path.parent, prefix=f".{self.path.name}-"
            )
            self._tmp = Path(name)
            self._out = os.fdopen(fd, "w", encoding="utf-8")
            for kept in self.page:
                self._write(kept)
        self._write(row)

    def finish(self) -> dict:
        result = {
            "matched": self.total,
            "returned": len(self.page),
            "truncated": self.total > len(self.page),
        }
        if self._out is not None:
            self._out.flush()
            os.fsync(self._out.fileno())
            self._out.close()
            assert self._tmp is not None
            os.replace(self._tmp, self.path)
            result["all_results"] = self.shown
            result["all_results_format"] = "JSON Lines, one complete result per line"
        return result


def ft_to_iso(ft):
    """A FILETIME (100 ns since 1601-01-01 UTC) as ISO 8601 UTC with seven fractional digits, by integer arithmetic."""
    try:
        whole, ticks = divmod(int(ft), 10_000_000)
        return (FILETIME_EPOCH + datetime.timedelta(seconds=whole)).strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % ticks
    except (TypeError, ValueError, OverflowError):
        return None


def rooted_key(hive, path):
    """The key at `path`, from the hive's root. regipy's get_key takes the
    first part of a path that does not start with a backslash for the root's
    own name and drops it: "Local Settings\\...\\BagMRU" in a UsrClass.dat was
    not found, and in an NTUSER.DAT it answered Software\\...\\BagMRU under
    the name asked for. The path is rooted here, the root's name dropped when
    the caller gave it, and / taken for \\."""
    parts = [p for p in str(path).replace("/", "\\").split("\\") if p]
    if parts and parts[0].lower() == (hive.root.name or "").lower():
        parts = parts[1:]
    return hive.get_key("\\" + "\\".join(parts)) if parts else hive.root


def nearest_key(hive, path):
    """Where `path` stops existing: the deepest key of it the hive has, the
    part that is not there, and the names that are. A caller who guessed a
    key (a printer key one Windows version keeps and another does not, a
    control set an offline SYSTEM hive numbers) picks from these instead of
    guessing again."""
    parts = [p for p in str(path).replace("/", "\\").split("\\") if p]
    if parts and parts[0].lower() == (hive.root.name or "").lower():
        parts = parts[1:]
    node, found = hive.root, []
    for part in parts:
        kids = list(node.iter_subkeys())
        match = next((k for k in kids if k.name.lower() == part.lower()), None)
        if match is None:
            return {"deepest_found": "\\" + "\\".join(found), "missing": part,
                    "subkeys_there": sorted(k.name for k in kids)}
        node, found = match, found + [match.name]
    return {"deepest_found": "\\" + "\\".join(found), "missing": None, "subkeys_there": []}


def hive_kind(hive):
    kind = getattr(hive, "hive_type", None)
    return str(kind).lower() if kind else None


SAM_USER_KEY = re.compile(r"\\domains\\account\\users\\[0-9a-f]{8}\\$")
CACHED_LOGON = re.compile(r"^NL\$", re.I)


def sensitive_value(key_path, name, vtype):
    """Whether this value is registry material that can be a secret (see the module note). Decided by the value's
    name and the key's place in the hive, never by what the hive file calls itself."""
    if vtype not in TEXT_OR_BINARY:
        return False
    name = name or ""
    if SENSITIVE_NAME.search(name) or CACHED_LOGON.match(name):
        return True
    path = "\\" + str(key_path).strip("\\").lower() + "\\"
    if "\\policy\\secrets\\" in path or path.endswith("\\policy\\polekl\\") or path.endswith("\\policy\\polsecretencryptionkey\\"):
        return True
    return bool(SAM_USER_KEY.search(path)) and name.lower() == "v"


def read_values(hive, k, key_path, withheld, problems):
    """Every value of key `k`, whole: the value as regipy decodes it (bytes as hex), its type and its length."""
    values, types, lengths, corrupted = {}, {}, {}, []
    try:
        # trim_values=False: the default cuts a binary value to 128 bytes and a string to 256 characters.
        for v in k.iter_values(trim_values=False):
            val = v.value
            length = len(val) if isinstance(val, (bytes, bytearray, str, list)) else None
            if isinstance(val, (bytes, bytearray)):
                val = bytes(val).hex()
            vtype = str(v.value_type)
            if sensitive_value(key_path, v.name, vtype):
                withheld.append({"key": key_path, "name": v.name, "type": vtype, "length": length})
                val = "[withheld: %s %s]" % (length, "bytes" if vtype in ("REG_BINARY", "REG_NONE") else "characters")
            values[v.name] = val
            types[v.name] = vtype
            lengths[v.name] = length
            if getattr(v, "is_corrupted", False):
                corrupted.append(v.name)
    except Exception as exc:                                  # a damaged value list: what was read is kept, the rest is named
        problems.append({"where": key_path, "what": "values", "error": "%s: %s" % (type(exc).__name__, exc)})
    return values, types, lengths, corrupted


def dump(hive, key, recurse=False, depth=2, limit=500, max_nodes=MAX_NODES):
    h = RegistryHive(hive)
    k = rooted_key(h, key)
    problems, withheld = [], []
    out = {"key": key, "values": {}, "subkeys": []}
    values, types, lengths, corrupted = read_values(h, k, key, withheld, problems)
    out["values"], out["value_types"], out["value_lengths"] = values, types, lengths
    if corrupted:
        out["corrupted_values"] = corrupted
    hdr = getattr(k, "header", None)
    if hdr is not None:
        out["last_modified"] = ft_to_iso(hdr.last_modified)
        out["last_modified_filetime"] = str(hdr.last_modified)
    nodes = LosslessPage("regkv", [hive, key, depth], limit)
    stopped = LosslessPage("regkv-stopped", [hive, key, depth], 50)
    seen = 0
    tree_complete = True
    # Breadth first from the key asked for: (a key's node, the list its entries go in, its path, its depth).
    queue = [(k, out["subkeys"], key, 0)]
    while queue:
        node, target, path, d = queue.pop(0)
        try:
            children = list(node.iter_subkeys())
        except Exception as exc:
            problems.append({"where": path, "what": "subkeys", "error": "%s: %s" % (type(exc).__name__, exc)})
            stopped.add({"path": path, "reason": "its subkeys could not be read", "error": "%s: %s" % (type(exc).__name__, exc)})
            continue
        for s in children:
            seen += 1
            entry = {"name": s.name, "subkeys": s.subkey_count, "values": s.values_count}
            sh = getattr(s, "header", None)
            if sh is not None:
                entry["last_modified"] = ft_to_iso(sh.last_modified)
                entry["last_modified_filetime"] = str(sh.last_modified)
            child_path = path + "\\" + s.name
            if seen <= INLINE_NODES:
                target.append(entry)
            else:
                tree_complete = False
            if recurse:
                nodes.add({"path": child_path, "depth": d + 1, "subkeys": s.subkey_count, "values": s.values_count,
                           "last_modified": entry.get("last_modified"), "last_modified_filetime": entry.get("last_modified_filetime")})
            if recurse and s.subkey_count:
                if d >= depth:
                    stopped.add({"path": child_path, "reason": "depth limit (%d)" % depth, "subkeys": s.subkey_count})
                elif seen >= max_nodes:
                    stopped.add({"path": child_path, "reason": "node limit (%d)" % max_nodes, "subkeys": s.subkey_count})
                else:
                    sub = []
                    if seen <= INLINE_NODES:
                        entry["subkey_list"] = sub
                    queue.append((s, sub, child_path, d + 1))
    out["tree_complete"] = tree_complete
    out["nodes_listed"] = seen
    stopped_page = stopped.finish()
    out["stopped_branches"] = stopped.page
    out["stopped_branch_count"] = stopped_page["matched"]
    if stopped_page.get("all_results"):
        out["all_stopped_branches"] = stopped_page["all_results"]
    node_page = nodes.finish()
    if recurse:
        out["nodes"] = nodes.page
        out["node_count"] = node_page["matched"]
        if node_page.get("all_results"):
            out["all_nodes"] = node_page["all_results"]
    out["problems"] = problems
    out["sensitive_values_withheld"] = withheld
    header = h.header
    out["hive_dirty"] = header.primary_sequence_num != header.secondary_sequence_num
    out["hive_sequence_numbers"] = [header.primary_sequence_num, header.secondary_sequence_num]
    out["transaction_logs_beside_hive"] = [hive + s for s in (".LOG1", ".LOG2", ".LOG") if os.path.isfile(hive + s)]
    out["transaction_logs_replayed"] = False
    out["hive_type"] = hive_kind(h)
    return out


def main():
    raw = sys.stdin.read()
    if not raw.strip():
        print(json.dumps({'error': 'no JSON input'})); sys.exit(1)
    try:
        args = json.loads(raw)
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": "arguments are not valid JSON", "reason": str(exc)})); sys.exit(1)
    hive = args.get('hive'); key = args.get('key')
    if not hive or key is None:
        print(json.dumps({'ok': False, 'error': 'hive and key are required'})); sys.exit(1)
    if not os.path.isfile(hive):
        print(json.dumps({'ok': False, 'error': 'no such hive', 'hive': hive})); sys.exit(1)
    recurse = bool(args.get('recurse', False))
    depth = args.get('depth', 2)
    limit = args.get('limit', 500)
    max_nodes = args.get('max_nodes', MAX_NODES)
    for name, v, low in (("depth", depth, 0), ("limit", limit, 1), ("max_nodes", max_nodes, 1)):
        if isinstance(v, bool) or not isinstance(v, int) or v < low:
            print(json.dumps({"ok": False, "error": "%s must be a whole number of at least %d" % (name, low), name: v})); sys.exit(1)
    try:
        out = dump(hive, key, recurse, depth, limit, max_nodes)
    except RegistryKeyNotFoundException:
        # The sixth CTF round's agent asked for ControlSet001\Enum\USBPRINT
        # and ...\Print\Printers and got regipy's traceback twice; the names
        # that are there are what it needed to ask again.
        where = nearest_key(RegistryHive(hive), key)
        print(json.dumps({'ok': False, 'error': 'key not found', 'key': key, **where}, indent=1)); sys.exit(1)
    except Exception as exc:                                  # not a hive, or one regipy cannot open
        print(json.dumps({"ok": False, "error": "could not read the hive", "hive": hive, "reason": "%s: %s" % (type(exc).__name__, exc)})); sys.exit(1)
    try:
        from importlib.metadata import version
        regipy_version = version("regipy")
    except Exception:
        regipy_version = None
    out = {"parser": PARSER, "regipy_version": regipy_version, "hive": hive,
           "status": "partial" if out["problems"] or out["stopped_branch_count"] else "complete", **out}
    print(json.dumps(out, indent=1, default=str))

if __name__ == '__main__':
    main()
