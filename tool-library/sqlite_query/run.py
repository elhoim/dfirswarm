import json, subprocess, sys, os, shlex
obj=json.load(sys.stdin)
db=obj['db_path']
sql=obj['sql']
csv=bool(obj.get('csv', False))
readonly=bool(obj.get('readonly', True))
if not os.path.exists(db):
    raise SystemExit(f'database not found: {db}')
# Use immutable URI for read-only safety when requested.
if readonly:
    db_arg=f'file:{db}?mode=ro&immutable=1'
    cmd=['sqlite3','-uri']
else:
    db_arg=db
    cmd=['sqlite3']
if csv:
    cmd += ['-header','-csv']
cmd += [db_arg, sql]
proc=subprocess.run(cmd, capture_output=True, text=True)
print(json.dumps({'ok': proc.returncode==0, 'returncode': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr}))
if proc.returncode != 0:
    raise SystemExit(proc.returncode)
