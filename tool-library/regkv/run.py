import sys, json, datetime
from regipy.registry import RegistryHive

def ft_to_iso(ft):
    # ft is FILETIME 100ns since 1601-01-01
    try:
        dt = datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=ft/10)
        return dt.strftime('%Y-%m-%dT%H:%M:%S.%fZ')
    except Exception:
        return str(ft)

def dump(hive, key, recurse=False, depth=2):
    h = RegistryHive(hive)
    k = h.get_key(key)
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
            node = h.get_key(node_path)
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
    hive = args['hive']; key = args['key']
    recurse = bool(args.get('recurse', False))
    depth = int(args.get('depth', 2))
    out = dump(hive, key, recurse, depth)
    print(json.dumps(out, indent=1, default=str))

if __name__ == '__main__':
    main()
