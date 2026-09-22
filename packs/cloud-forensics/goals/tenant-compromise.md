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

## Definition of done

`work/report.md` exists and answers questions 1 to 7 under the headings `## 1.`
through `## 7.`. Answer 6 states the revocation times, not only the reset time.
Answer 7 names at least one thing the tenant's configuration made unanswerable,
or says explicitly that everything needed was enabled. A critic has read it
against the board and posted a sign-off. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'retention|revok' work/report.md`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 5`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"skill"' traces/events.jsonl`
