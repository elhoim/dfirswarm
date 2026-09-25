import sys, json, datetime, os
from regipy.registry import RegistryHive
from regipy.exceptions import RegistryKeyNotFoundException

def ft_to_iso(ft):
    # ft is FILETIME 100ns since 1601-01-01
    try:
        dt = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=ft/10)
        return dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    except Exception:
        return str(ft)

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


def dump(hive, key, recurse=False, depth=2):
    h = RegistryHive(hive)
    k = rooted_key(h, key)
    out = {'key': key, 'values': {}, 'subkeys': []}
    for v in k.iter_values():
        val = v.value
        if isinstance(val, bytes):
            val = val.hex()
        out['values'][v.name] = val
    hdr = getattr(k, 'header', None)
    if hdr is not None:
        out['last_modified'] = ft_to_iso(hdr.last_modified)
    def walk(node_path, d):
        try:
            node = rooted_key(h, node_path)
        except Exception:
            return []
        res = []
        for s in node.iter_subkeys():
            name = s.name
            entry = {'name': name, 'subkeys': s.subkey_count, 'values': s.values_count}
            sh = getattr(s, 'header', None)
            if sh is not None:
                entry['last_modified'] = ft_to_iso(sh.last_modified)
            if recurse and d < depth:
                entry['subkey_list'] = walk(node_path + '\\' + name, d+1)
            res.append(entry)
        return res
    out['subkeys'] = walk(key, 0)
    return out

def main():
    raw = sys.stdin.read()
    if not raw.strip():
        print(json.dumps({'error': 'no JSON input'})); sys.exit(1)
    args = json.loads(raw)
    hive = args.get('hive'); key = args.get('key')
    if not hive or key is None:
        print(json.dumps({'ok': False, 'error': 'hive and key are required'})); sys.exit(1)
    if not os.path.isfile(hive):
        print(json.dumps({'ok': False, 'error': 'no such hive', 'hive': hive})); sys.exit(1)
    recurse = bool(args.get('recurse', False))
    depth = int(args.get('depth', 2))
    try:
        out = dump(hive, key, recurse, depth)
    except RegistryKeyNotFoundException:
        # The sixth CTF round's agent asked for ControlSet001\Enum\USBPRINT
        # and ...\Print\Printers and got regipy's traceback twice; the names
        # that are there are what it needed to ask again.
        where = nearest_key(RegistryHive(hive), key)
        print(json.dumps({'ok': False, 'error': 'key not found', 'key': key, **where}, indent=1)); sys.exit(1)
    print(json.dumps(out, indent=1, default=str))

if __name__ == '__main__':
    main()
