# A ransomware incident

Establish what happened, in the order the organisation needs it: scope, then
what left, then how they got in, then what the encryptor did.

Read the skill index with `skill()` first. `scope/first-hour` sets the order and
explains why exfiltration is question three and not question seven.

## Questions

1. Scope: which machines, what proportion of each is encrypted, and the window
   the modification times bracket on each one.
2. Exfiltration: what left, by what route, how much, and when — stated as one of
   three positions: evidenced; not evidenced with the logging present; not
   evidenced with the logging absent.
3. Entry and dwell: how the operator first got in, and the earliest artefact you
   can tie to them. The encryption is the last event, not the first.
4. Spread: how the encryptor reached each machine, and from which one.
5. Destruction: shadow copies, backups, catalogues, boot recovery and stopped
   services — what was destroyed deliberately, as distinct from encrypted.
6. Identification: the family and affiliate, with the note, the file marker and
   the binary agreeing, or a statement of which of them you have.
7. Recovery: what was never encrypted, what survives elsewhere, what is only
   partially encrypted, and what is genuinely gone.
8. Whether the operator may still have access, as a position with reasons.
9. The timeline in UTC, and what evidence was lost to the response itself.

## Definition of done

`work/report.md` exists and answers questions 1 to 9 under the headings `## 1.`
through `## 9.`. Answer 2 states which of the three exfiltration positions
applies. Answer 8 is a position, not a shrug. No credential, wallet address or
victim identifier appears in the body; identifiers go in an appendix. A critic
has read it against the board and posted a sign-off as a `result`
post that starts a line with `SIGN-OFF:` and names what they verified. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8 9; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'UTC' work/report.md`
- `grep -qiE 'not evidenced|evidenced' work/report.md`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 8`
- `awk 'FNR==1{r=0} /^tag: result$/{r=1} r&&/^\**SIGN-OFF/{m=1;exit} END{exit !m}' threads/main/*.md`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
