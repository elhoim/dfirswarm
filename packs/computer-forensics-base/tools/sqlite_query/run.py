import json, subprocess, sys, os, shlex, urllib.parse
obj=json.load(sys.stdin)
db=obj['db_path']
sql=obj['sql']
csv=bool(obj.get('csv', False))
readonly=bool(obj.get('readonly', True))
if not os.path.exists(db):
    raise SystemExit(f'database not found: {db}')
# Use immutable URI for read-only safety when requested. The sqlite3 shell
# reads a file: name as a URI by itself; it has no -uri option (every call
# with readonly=true failed on "unknown option: -uri"). immutable=1 also opens
# a WAL database on a read-only mount, where plain mode=ro cannot create -shm.
# The path is percent-encoded: a "#" or "?" in it would end the name early.
if readonly:
    db_arg=f'file:{urllib.parse.quote(db)}?mode=ro&immutable=1'
else:
    db_arg=db
cmd=['sqlite3']
# -csv before -header: a newer shell (3.54) resets the header switch when
# -csv sets the mode, and "-header -csv" printed the rows without one.
if csv:
    cmd += ['-csv','-header']
cmd += [db_arg, sql]
proc=subprocess.run(cmd, capture_output=True, text=True)
print(json.dumps({'ok': proc.returncode==0, 'returncode': proc.returncode, 'stdout': proc.stdout, 'stderr': proc.stderr}))
if proc.returncode != 0:
    raise SystemExit(proc.returncode)
