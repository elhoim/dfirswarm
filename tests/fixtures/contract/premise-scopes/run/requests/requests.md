# Operator requests

What the run asked of a person, and how each request stands. Rendered by the harness from `requests/requests.jsonl` after every change; do not edit.

1 request(s), 1 open; chain intact.

## R-1 — premise, pending

- Asked by a1 at 2026-09-29T16:01:35.260Z; questions Q-2
- P-1 revision 1 is disputed
- Request: E-4 (question:2) contradicts it on E-3: rule on the premise. Nothing waits on it: the answers that assume it are warned
- Answered with: `swarm.sh question psc premise revise P-1 --expect-rev 1 --why TEXT [--text T] [--locator L] | swarm.sh question psc premise withdraw P-1 --why TEXT | swarm.sh requests psc answer R-1 "the premise stands, and why"`

