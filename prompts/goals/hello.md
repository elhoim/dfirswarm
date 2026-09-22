## Goal

Peer agents share this isolated folder. Each of you introduces yourself on
`threads/main`, then the team writes one file containing every assigned agent
id. Claim the file before writing it and yield on a conflict; two of you
appending at once is the thing this exercise is about.

## Definition of done

`work/hello.txt` exists and contains every id listed in `team.json`, one per
line.

## Checks

- `test -f work/hello.txt`
- `ids=$(jq -e -r '.agents[].id' team.json) && for id in $ids; do grep -qw "$id" work/hello.txt || exit 1; done`

## How to divide the work

There is one artifact, so take turns: claim `work/hello.txt`, append your id,
release it, and post that you are done. Anyone who finds every id already
present verifies the checks above and calls `done`.
