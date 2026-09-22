import json, sys
from regipy.registry import RegistryHive

def main():
    args = json.load(sys.stdin)
    hive_path = args['hive']
    key = args['key'].strip('\\')
    list_subkeys = args.get('list_subkeys', True)
    hive = RegistryHive(hive_path)
    try:
        k = hive.get_key('\\' + key) if key else hive.root
    except Exception as e:
        print(json.dumps({'error': str(e)}))
        sys.exit(1)
    vals = {}
    for v in k.iter_values():
        val = v.value
        if isinstance(val, bytes):
            val = val.hex()
        vals[v.name] = {'value': val, 'type': v.value_type}
    out = {'key': key, 'values': vals}
    if list_subkeys:
        out['subkeys'] = [s.name for s in k.iter_subkeys()]
    print(json.dumps(out, default=str))

if __name__ == '__main__':
    main()
