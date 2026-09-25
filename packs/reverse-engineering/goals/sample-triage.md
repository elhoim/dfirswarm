# What is this file, and what was it built to do

A sample recovered from a case, and the question of what it is. Static analysis
only: nothing here is executed, and the report must say so.

Read the skill index with `skill()` first. `triage/quarantine` sets the order
and the rules; every claim in this report is a claim about the file, not about
its behaviour on any machine.

## Questions

1. What the file is, from its bytes rather than its name, with its sha256 and
   whether the extension agrees.
2. Structure: sections or segments, their sizes and permissions, the entropy
   profile, and whether any of it is packed.
3. What it declares: imports, exports, linked libraries, and the version
   information or original file name where there is one.
4. What it can do: the capabilities mapped from the code, each with the address
   behind it.
5. Strings that matter, including the obfuscated ones, each with the function
   that references it — or a plain statement that nothing references it.
6. Indicators another examiner could search for: hashes, mutexes, domains,
   paths, and a rule if you wrote one, with what it was built from.
7. What you could not establish, and what would be needed to establish it.

## Definition of done

`work/report.md` exists and answers questions 1 to 7 under the headings `## 1.`
through `## 7.`. The report states that the sample was not executed. Every
capability claim carries an address or an import. A critic has read it against
the board and posted a sign-off as a `result`
post that starts a line with `SIGN-OFF:` and names what they verified. `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7; do grep -q "^## $n\." work/report.md || exit 1; done`
- `grep -qiE 'not executed|static analysis only|no dynamic analysis' work/report.md`
- `grep -qE '[0-9a-f]{64}' work/report.md`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 3`
- `awk 'FNR==1{r=0} /^tag: result$/{r=1} r&&/^\**SIGN-OFF/{m=1;exit} END{exit !m}' threads/main/*.md`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
- `grep -q '"tool":"skill"' traces/events.jsonl`
