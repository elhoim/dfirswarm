# Use case: Challenge #8, NTFS Hidden Files

The swarm on this case: what was asked, who did what, what the harness did, what it cost, and everything the agents wrote, with the console and the terminals captured while they worked. The case is [https://www.ashemery.com/dfir.html#Challenge8](https://www.ashemery.com/dfir.html#Challenge8) (Ali Hadi, Digital Forensic Challenge Images); the evidence files are not in this repository.

| | |
| --- | --- |
| Run | `sfcc3`, 2026-09-18T15:17:52Z → sentinel 2026-09-18T15:57:35.534Z (**39.7 minutes**) |
| Team | 5 agents: 2 × `azure-foundry/grok-4.6`, 3 × `azure-foundry/DeepSeek-V4-Pro` |
| Evidence | `inputs/CASE.md`, `inputs/NTFS-HiddenFiles.E01`, `inputs/NTFS-HiddenFiles.E01.txt`, read-only at the kernel in every pane (`seatbelt`) |
| Flags | `--catalog --toolbox dfir --quarantine  --cap-per-agent 12 --allow-host isf-server.techanarchy.net --allow-tool-forging --cap-usd 60 --wall-clock 180` |
| Outcome | `work/report.md` under the required headings, `work/timeline.md` with 28 dated rows, ledger of 58 entries (28 events, 19 indicators, 11 findings); **7/7 checks** pass |
| Cost | **$40.78** of the $60.00 cap, 288 model calls, 28.7M tokens; $12.33 on grok-4.6, $28.45 on DeepSeek-V4-Pro |
| Harness | 63 shell writes taken as implicit claims, 0 claim violations, 2 forged tools called 5 times (8 `make_tool` calls, 6 refused for a reserved name), 6 forge hints, 4 idle nudges, 1 sentinel nudge, 0 writes to `inputs/` |

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm. The questions, verbatim:

1. Hidden item 1: what it is (name, size, hash, content), where it is hidden, and the command that reveals it.
2. Hidden item 2: the same.
3. Hidden item 3: the same.
4. Hidden item 4: the same.
5. Hidden item 5: the same.
6. The five hiding techniques (alternate data streams, streams on directories, $EA or other attributes, resident data in odd places, deleted or renamed entries, unallocated or slack space, attribute tricks, timestomping) each with the detection method and the NTFS structure involved; plus anything else hidden beyond the five.

## What the agents did

The image is small — a 97 MB NTFS logical volume with no partition table, 464 KB
compressed as an E01 — and the whole case is a puzzle about the file system
itself. Five things are hidden in it and the examiner has to say how.

**The first pass did most of the finding.** `--catalog` ran before the agents
started and wrote the partition answer (there is none: the E01 holds a logical
volume, which the catalog handles since PR #17), the file list and the MAC
timeline. The disk seat read it and had three of the five items inside four
minutes, because `fls -r` prints a named stream with a colon and a directory
that carries one as `d/r`:

```
r/r 168-128-4:  README.txt:Secrets.txt
d/r 169-128-4:  Photos:flag1.jpg
d/r 170-128-4:  Tools:flag2.jpg
```

**The fourth and fifth took the rest of the run.** `Tools:flag2.jpg` is not a
JPEG: `icat 170-128-4 | file -` says Zip archive, and inside it is NirSoft's
`AlternateStreamView.exe` with its help file — the tool that reveals streams,
hidden in a stream. The analysis seat unzipped it under `work/extracted/`,
where quarantine had already stripped the execute bit, and read the PE header
rather than running it.

The fifth item is the one the swarm argued about. A `$Quota` file sits at the
volume root as inode 15, which is not where NTFS keeps quotas (that is
`$Extend/$Quota`, inode 24). Its directory entry had been removed from the
root index and its attribute flags changed from Hidden+System to Archive, so
`chkdsk` had found it as an orphan and recovered it — and said so in a log the
seats read at inode 18:

```
file attributes flag 0x20 in file 0xf is incorrect. The expected value is 0x26
Recovering orphaned file $Quota (F) into directory file 5
```

Then the timeline seat pulled `$MFT` record 171 raw and found, past the end of
the last attribute, a UTF-16LE string in the record's unused tail:

```
Hash for flag2: 7BC9D240F9EB3CC42B450ED568AAD599
```

which is the MD5 of the ZIP from item 3. The disk seat verified that
cross-reference independently, and the critic verified it again before the
sign-off. The five techniques the report names are: a stream on a file, a
stream on a directory, a stream on a directory whose content lies about its
type, a record's slack in `$MFT`, and an unlinked file with tampered flags and
a timestomp.

**What the harness showed.** Nothing had to be steered: no cap steer, no
reaping, no claim violation in 63 implicit claims, and `inputs/` came through
byte for byte, checked three times. Six forge hints fired, all on real
repetition (`fls` eight times, `icat` forty-five). Two tools were forged and
one of them, `extract_stream`, was never called by anyone including its author.

**The one thing that went wrong is in the goal document, not the harness.**
The checks include `grep -q '"tool":"inputs_check"' traces/events.jsonl`, and
`inputs_check` is the name of a harness *event*, emitted by `done` when it
verifies the inputs on the way out. Every seat read it as the name of a tool
it had to provide. Every one of the five tried to forge it and the reserved-name
rule from challenge 2 refused them six times; one forged `check_inputs`
instead and called it five times, and the critic's sign-off ends with an open
question about whether that is acceptable. It was: `done` emitted the event a minute later and the check
passed 7 of 7. The cost of the confusion is the forged tool, its five calls
and several minutes of three agents' attention. A check should name the tool
the examiner must call, and `make_tool` refusing a reserved name should say
which built-in emits it. That is A20 in the improvement plan.

**Azure, the second time.** Five seats, two Grok 4.6 and three DeepSeek V4
Pro, on one Foundry resource. The split of the work is the same as on the
seventh case: the DeepSeek seats make many small calls (216 between three of
them) and the Grok seats fewer and larger (72 between two), and this time the
DeepSeek seats carried 70 % of the bill on a case whose evidence is 464 KB.
$40.78 for a small image is the run's real lesson about cost: the money went
into 28.7M tokens of context, not into reading the disk.

The answers are in [`run/work/report.md`](run/work/report.md); the notes each seat kept are next to it under [`run/work/`](run/work/), the merged timeline is [`run/work/timeline.md`](run/work/timeline.md), and the ledger the timeline was built from is [`run/ledger.md`](run/ledger.md). The board is under [`run/board/`](run/board/), the raw trace is [`run/trace/events.jsonl`](run/trace/events.jsonl), and [`run/summary.md`](run/summary.md) is the summary `scripts/summary.ts` wrote.

## What the harness did, by the numbers

| Signal | Count |
| --- | --- |
| trace events | 823 |
| bash calls | 251 |
| posts | 23 on 1 thread(s) |
| implicit claims (shell writes turned into claims) | 63 |
| claim violations | 0 |
| forge hints | 6 |
| forged tools | `extract_stream` by sfcc303 (0 calls), `inputs_check` by sfcc304 (0 calls), `check_inputs` by sfcc304 (5 calls), `inputs_check` by sfcc304 (0 calls), `inputs_check` by sfcc301 (0 calls), `inputs_check` by sfcc300 (0 calls), `inputs_check` by sfcc304 (0 calls), `inputs_check` by sfcc302 (0 calls) |
| idle nudges | 4 |
| sentinel nudge | reached 4, missed 0 |
| inputs checks | 3 |
| writes to inputs/ | 0 |
| per-agent cap steers / stops | 0 / 0 |
| ledger entries | 58 (28 events, 19 indicators, 11 findings) by 5 agents |

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens |
| --- | --- | --- | --- | --- | --- |
| sfcc303 | Timeline and ledger | DeepSeek-V4-Pro | $9.53 | 68 | 7.5M |
| sfcc304 | Critic and editor | DeepSeek-V4-Pro | $9.52 | 75 | 7.0M |
| sfcc302 | Recovery and analysis | DeepSeek-V4-Pro | $9.41 | 73 | 7.7M |
| sfcc301 | Artifacts and execution | grok-4.6 | $6.70 | 41 | 3.6M |
| sfcc300 | Disk and file system | grok-4.6 | $5.63 | 31 | 2.9M |

| Model | Spend | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| `azure-foundry/DeepSeek-V4-Pro` | $28.45 | 70 % | 216 | 3 |
| `azure-foundry/grok-4.6` | $12.33 | 30 % | 72 | 2 |

## Screenshots

The console at 8941 after the run (only forensic runs are listed on it):

- [`01-overview-final.png`](screenshots/01-overview-final.png) — the run page: the finish line certified 7 of 7, the board, the seats.
- [`02-ledger-final.png`](screenshots/02-ledger-final.png) — the Ledger tab: 58 entries, the events the timeline rests on.
- [`03-budget-final.png`](screenshots/03-budget-final.png) — the Budget tab: $40.78 of $60, per agent and per model.
- [`04-tools-final.png`](screenshots/04-tools-final.png) — the Tools tab: `extract_stream` and `check_inputs` with their manifests and call counts.

## Reproducing it

Get the evidence from the source above into one directory, install `sleuthkit`, `libewf`, `yara` and `foremost` (brew) and `volatility3` (pipx), start Herdr, and run:

```
scripts/swarm.sh start --models "openai/gpt-5.4=4,deepseek/deepseek-v4-pro=3" --cap-usd 60 --wall-clock 180 \
  --goal-file goal.md --inputs <evidence dir> --inputs-max-mb 60000 --catalog --toolbox dfir --quarantine  --cap-per-agent 12 --allow-host isf-server.techanarchy.net --allow-tool-forging \
  --case-id AH-C08 --examiner "<name>"
```
