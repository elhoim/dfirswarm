# Use case: Challenge #9, Encrypt Them All

The swarm on this case: what was asked, who did what, what the harness did, what it cost, and everything the agents wrote, with the console and the terminals captured while they worked. The case is [https://www.ashemery.com/dfir.html#Challenge9](https://www.ashemery.com/dfir.html#Challenge9) (Ali Hadi, Digital Forensic Challenge Images); the evidence files are not in this repository.

| | |
| --- | --- |
| Run | `s864a`, 2026-09-18T16:04:48Z → stopped by the examiner 2026-09-18T17:37:41.667Z (**92.9 minutes**), **no sentinel**: two seats stalled holding claims and the swarm never signed off |
| Team | 9 agents: 4 × `azure-foundry/grok-4.6`, 5 × `azure-foundry/DeepSeek-V4-Pro` |
| Evidence | `inputs/AF-Case2.E01` (7.9 GB), `inputs/CASE.md`, read-only at the kernel in every pane (`seatbelt`) |
| Flags | `--catalog --toolbox dfir --quarantine  --cap-per-agent 15 --allow-host isf-server.techanarchy.net --allow-tool-forging --cap-usd 110 --wall-clock 240` |
| Outcome | `work/report.md` under the required headings, `work/timeline.md` with 41 dated rows, ledger of 141 entries (89 events, 23 indicators, 29 findings); **6/7 checks** pass |
| Cost | **$108.48** of the $110.00 cap, 746 model calls, 73.1M tokens; $55.53 on grok-4.6, $52.95 on DeepSeek-V4-Pro |
| Harness | 308 shell writes taken as implicit claims, 9 claim violations (all on the shared `work/extracted/`), 5 forged tools called 13 times, 9 forge hints, 13 idle nudges, 0 per-agent cap steers although one seat passed the cap, 0 writes to `inputs/` |

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm. The questions, verbatim:

1. Lost in Space: the README — where it is, how it was encrypted, how you recovered the plaintext or the password (browser or application caches, shell and PowerShell history, an earlier copy in $LogFile/$UsnJrnl/volume shadow copies/unallocated space), and what it says.
2. Do Not Be Deceived: the R2D2 BitLocker volume — where it is, how the recovery key or password was found, how the volume was decrypted (state exactly what the host lacks if a step could not be done here), and what was hidden inside.
3. Your Focus Determines Your Reality: the key pair — where the keys were, the keys file in Downloads, the decrypted message, and what it was used for.
4. The timeline of Jane's encryption activity and the communication, and how the three parts connect.
5. Approach, tools forged, what remains uncertain, and anything else the examiner should know.

## What the agents did

This case is three investigations in one 7.9 GB image, so it ran nine seats
rather than the usual seven: two more for the parts that needed their own
hands, BitLocker and cryptography, and one for recovery from the file system
journals. It is also the first run here that did not finish. It answered two
of the three parts, documented the third as a gap, was stopped a dollar and a
half short of its cap, and left two TODO markers in the report because the two
seats holding the answers stopped mid-turn. What follows is what happened,
including the parts that did not work.

**Part 1, the README.** The caches seat found the communication where the
brief says to look for it: a Mattermost conversation in the Edge cache, with
the AES password `StarWars!` in plain text. The recovery seat proved the
plaintext was not anywhere else — not in `$LogFile`, whose records are
wrapped; not in `$UsnJrnl`, which keeps names and not content; no volume
shadow copies; nothing in the Recycle Bin, the pagefile or the reused MFT
record. That negative matters: it says the password was the only way in.

Then the run hit a wall that was not the case's fault. The file is AES Crypt
v2, and this host has `openssl` and `gpg` but neither `aescrypt` nor
`pyAesCrypt`, and netguard keeps PyPI out of the sandbox. One seat spent
several minutes reimplementing the AES Crypt key derivation by hand, 8192
rounds of SHA-256, both text encodings, CBC and ECB, and got a header parse
but no plaintext. **The examiner installed `pyAesCrypt` on the host from
outside the sandbox**, and the seats found it on their next import: part 1
decrypted, HMAC verified, the plaintext under `work/extracted/README.txt`.
That intervention is the reason this part has an answer, and it is the clearest
argument for the two changes the run asks for: a per-case toolbox, and a way
to hand a tool to a swarm that is already running.

**Part 2, BitLocker.** The disk seat found the trick without decrypting
anything. There are two volumes named R2D2: the one in Documents is an
unencrypted clone, the one under ProgramData is the BitLocker target, and the
clone carries `DeceiveYou.png`, which reads "Your eyes can deceive you! R2D2
has been cloned :P". The seat located the FVE metadata and the recovery key,
and said plainly what this host cannot do: there is no `dislocker` and no
root, so the volume itself was never opened. `work/bitlocker.md` documents the
gap rather than guessing, which is the right answer for a report that has to
stand up.

**Part 3, the key pair.** The keys were found and the GPG material identified;
the passphrase was not recovered, and a brute force over common candidates
failed. The timeline seat tied the three parts together from the ledger:
Defender disabled, the hosts entry for the case domain, the password shared in
Mattermost, the README encrypted and deleted, the twin volumes created and
cloned, the keys generated and John's key imported, the keys file encrypted
and posted.

**Where it stopped.** At 17:04 the cryptography seat claimed `work/crypto.md`
and the critic claimed `work/report.md`, and both went silent. Thirty-three
minutes later neither had written a byte and neither had been nudged again:
the idle nudge gives each agent three tries and both had spent theirs. The
report still carries `[TODO: decrypt result from s864a06]` and
`[TODO: decrypt result from s864a05]`, two lines from the answers that exist
elsewhere in the run. Their claims were still live when the swarm was stopped.
An agent that ends a turn holding a claim and never takes another blocks the
file it owns, and nothing in the harness notices.

**What the run showed about cost.** Nine seats cost $108.48 against a $110
cap, 73M tokens in an hour and a half. The four Grok seats spent $55.53 on 242
calls, the five DeepSeek seats $52.95 on 504. Four seats ended between $14.08
and $14.87 against a $15 per-agent cap, and one, the cryptography seat, ended
at **$16.26 — over the cap, with no steer and no stop**. That is not restraint
by the harness: the per-agent cap has never been armed in any run. The kickoff
writes `cap_per_agent_usd` into `budget.json`, and the first time an agent's
usage is folded in, `normalizeBudget` rebuilds the record without that field,
so the cap reads as zero from then on. Every "0 steers, 0 stops" line in the
earlier cases means only that nobody was ever checked. That is A21, and it is
fixed in the same pull request as this document.

**What nine seats did to the shared extraction root.** 308 shell writes became
implicit claims and nine of them were real collisions, all of them under
`work/extracted/`, where several seats pulled the same caches and hives at the
same time. With seven seats this was a nuisance; with nine it is a pattern.
That is A18, still planned.

The answers are in [`run/work/report.md`](run/work/report.md); the notes each seat kept are next to it under [`run/work/`](run/work/), the merged timeline is [`run/work/timeline.md`](run/work/timeline.md), and the ledger the timeline was built from is [`run/ledger.md`](run/ledger.md). The board is under [`run/board/`](run/board/), the raw trace is [`run/trace/events.jsonl`](run/trace/events.jsonl), and [`run/summary.md`](run/summary.md) is the summary `scripts/summary.ts` wrote.

## What the harness did, by the numbers

| Signal | Count |
| --- | --- |
| trace events | 1966 |
| bash calls | 509 |
| posts | 39 on 1 thread(s) |
| implicit claims (shell writes turned into claims) | 308 |
| claim violations | 9 |
| forge hints | 9 |
| forged tools | `grep_filelist` by s864a08 (0 calls), `icat_extract` by s864a08 (1 calls), `catalog_grep` by s864a02 (11 calls), `fve_metadata` by s864a05 (1 calls), `aescrypt_v2_decrypt` by s864a02 (0 calls) |
| idle nudges | 13 |
| sentinel nudge | — |
| inputs checks | 0 |
| writes to inputs/ | 0 |
| per-agent cap steers / stops | 0 / 0 |
| ledger entries | 141 (89 events, 23 indicators, 29 findings) by 8 agents |

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens |
| --- | --- | --- | --- | --- | --- |
| s864a06 | Key material and cryptography (parts 1 and 3) | DeepSeek-V4-Pro | $16.26 | 125 | 14.0M |
| s864a02 | Browser and application caches | grok-4.6 | $14.87 | 62 | 7.9M |
| s864a07 | Timeline and ledger | DeepSeek-V4-Pro | $14.83 | 109 | 11.0M |
| s864a01 | Recovery from file system journals | grok-4.6 | $14.59 | 61 | 7.5M |
| s864a00 | Disk and file system | grok-4.6 | $14.08 | 64 | 7.4M |
| s864a03 | Registry and execution | grok-4.6 | $11.99 | 55 | 6.3M |
| s864a08 | Critic and editor | DeepSeek-V4-Pro | $10.49 | 133 | 10.0M |
| s864a04 | Shell and user activity | DeepSeek-V4-Pro | $8.95 | 87 | 6.2M |
| s864a05 | BitLocker and volume encryption (part 2) | DeepSeek-V4-Pro | $2.42 | 50 | 2.8M |

| Model | Spend | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| `azure-foundry/grok-4.6` | $55.53 | 51 % | 242 | 4 |
| `azure-foundry/DeepSeek-V4-Pro` | $52.95 | 49 % | 504 | 5 |

Each agent's terminal as it stood at the last round captured before the run was stopped is under [`run/panes/`](run/panes/) — 9 panes, one per agent.

## Screenshots

The console at 8941, three of them while the swarm was still working:

- [`01-story-live.png`](screenshots/01-story-live.png) — the board at minute 64: nine seats, the AES wall, the twin R2D2 volumes.
- [`02-ledger-live.png`](screenshots/02-ledger-live.png) — the Ledger tab filling up, 129 entries at that moment.
- [`03-agents-live.png`](screenshots/03-agents-live.png) — the nine seats with their models, spend and context.
- [`04-budget-final.png`](screenshots/04-budget-final.png) — the Budget tab after the stop: $108.48 of $110, and the seat that ended over the per-agent cap.
- [`05-claims-final.png`](screenshots/05-claims-final.png) — the Claims tab: the nine collisions, and the two claims still held by the stalled seats.

## Reproducing it

Get the evidence from the source above into one directory, install `sleuthkit`, `libewf`, `yara` and `foremost` (brew) and `volatility3` (pipx), start Herdr, and run:

```
scripts/swarm.sh start --models "openai/gpt-5.4=4,deepseek/deepseek-v4-pro=3" --cap-usd 110 --wall-clock 240 \
  --goal-file goal.md --inputs <evidence dir> --inputs-max-mb 60000 --catalog --toolbox dfir --quarantine  --cap-per-agent 15 --allow-host isf-server.techanarchy.net --allow-tool-forging \
  --case-id AH-C09 --examiner "<name>"
```
