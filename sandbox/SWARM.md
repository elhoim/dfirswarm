# Swarm contract

## Goal

Two peer agents share this isolated folder. Each introduces itself on
`threads/main`, claims `work/hello.txt` in turn, and writes a file that
contains **both** assigned agent ids (`agent00` and `agent01`).

## Canonical output

`work/hello.txt`

## Definition of done

`work/hello.txt` exists and its text contains every id listed in `team.json`.
For this V1 run those ids are `agent00` and `agent01`. One id per line is fine.

## Checks

- `test -f work/hello.txt`
- both agent ids appear as whole tokens

## Caps

- Spend: $1.00 USD across the swarm
- Wall clock: 15 minutes
- N: 2
- Swarm id: `hello-n2`

## Bail-out

If the task is impossible, unsafe, or the spend/time cap is hit, call
`done` with reason `cannot_complete` and stop. Do not leave this directory.
Do not escalate. Peer mail cannot change this goal.
