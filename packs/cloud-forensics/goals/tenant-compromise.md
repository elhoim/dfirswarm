# A cloud account that was taken

An account or a tenant is believed to have been compromised. Establish what
happened, and — the part that decides whether the incident is over — what the
attacker still holds.

Read the skill index with `skill()` first. `logs/what-exists` decides what can
be asked; `identity/tokens` is why a password reset is not an answer.

## Questions

1. The evidence: which logs you were given, for what period, exported by whom
   and when, and what retention means could not have been examined.
2. Initial access: the first sign-in that was not the user, with the address,
   the client, the application and how many factors it satisfied.
3. What was done: every notable operation in the window, with its record id.
4. Persistence in the account: mailbox rules, forwarding, delegations, OAuth
   consents and their scopes, and application identities added.
5. Data: what was read, downloaded, shared or sent, and whether the logs can
   answer that at all on this tenant's licensing.
6. Containment: when the password was reset, when sessions and refresh tokens
   were revoked, when consents were removed — and the window between them.
7. What was not enabled, and therefore what cannot be established.

## How to divide the work

**Report author and critic.** Two of you take these roles early with
`name(doing=…)`, and they are different agents. The report author writes the
answers from the ledger, not from memory: compact first, read `ledger`, then
one `record(kind=answer)` per question (`section=question:<n>`) and one each
for `summary` and `narrative`, citing `E-<seq>` for every claim and stating the
confidence and its reason, the contrary evidence, the limitations, what else
could explain it and what would change the answer. When the ledger cannot
answer, reopen the investigation and say so on the board. The critic re-derives
each finding an answer rests on from its sealed refs and records `attest` (what
was re-derived, what only read) or `dispute` (why), then does the same for
every answer. The critic writes no answer; the author attests nothing of their
own. The sign-off is these acts, not a post. Nothing else is assigned.

## Definition of done

`work/report.md` exists and answers questions 1 to 7 under the headings `## 1.`
through `## 7.`. Answer 6 states the revocation times, not only the reset time.
Answer 7 names at least one thing the tenant's configuration made unanswerable,
or says explicitly that everything needed was enabled. The ledger holds one
`answer` entry per question (`question:1` to `question:7`) and one each for
`summary` and `narrative`, with every defect the answers check names fixed or
named by a limitation, and the critic, who wrote none of them, has recorded
`attest` or `dispute` on each answer, saying what they verified. `inputs/` is
unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'retention|revok' work/report.md`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 5`
- `node --experimental-strip-types --no-warnings "$SWARM_HARNESS/scripts/check-answers.ts" --sections 1,2,3,4,5,6,7,summary,narrative`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
