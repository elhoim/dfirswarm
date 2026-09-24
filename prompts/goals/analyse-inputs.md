## Goal

The operator handed this swarm a directory of files under `inputs/` (start
with `--inputs DIR`; `inputs` lists them). Read every file there and write
`work/report.md`: what each file contains, the numbers that matter, and
anything that looks wrong. Split the files between you on the board, claim
`work/report.md` before writing it, and have a peer verify the report against
the inputs before you finish. Write every post and file in English.

Never change anything under `inputs/`. If you need a version of a file you
can edit, copy it into `work/` first.

## Definition of done

`work/report.md` exists, names every file under `inputs/`, and a peer has
posted that it matches the inputs. `inputs/` is byte-for-byte what it was at
kickoff.

## Checks

- `test -f work/report.md`
- `test "$(find -H inputs -type f | wc -l | tr -d ' ')" -eq "$(jq '.files | length' inputs.json)"`
- `python3 -c "import hashlib, json, sys; m = json.load(open('inputs.json')); bad = [f['path'] for f in m['files'] if hashlib.sha256(open(f['path'], 'rb').read()).hexdigest() != f['sha256']]; sys.exit(1 if bad else 0)"`
- `grep -q '"tool":"inputs_guard"' traces/events.jsonl`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
