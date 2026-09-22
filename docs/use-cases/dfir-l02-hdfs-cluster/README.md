# Use case: Linux #2, Compromised HDFS Cluster

The swarm on this case: what was asked, who did what, what the harness did, what it cost, and everything the agents wrote, with the console and the terminals captured while they worked. The case is [https://www.ashemery.com/dfir.html#Linux2](https://www.ashemery.com/dfir.html#Linux2) (Ali Hadi, Digital Forensic Challenge Images); the evidence files are not in this repository.

| | |
| --- | --- |
| Run | `s9a5f`, 2026-09-18T23:08:28Z → sentinel 2026-09-18T23:32:38.804Z (**24.2 minutes**) |
| Team | 7 agents: 4 × `azure-foundry/grok-4.6`, 3 × `azure-foundry/DeepSeek-V4-Pro` |
| Evidence | `inputs/CASE-manual.txt`, `inputs/Case2-Workshop-Manual.pdf`, `inputs/HDFS-Master.E01` (3.3 GB), `inputs/HDFS-Master.E01.csv`, `inputs/HDFS-Master.E01.txt`, `inputs/HDFS-Slave1.E01` (3.2 GB), `inputs/HDFS-Slave1.E01.csv`, `inputs/HDFS-Slave1.E01.txt`, `inputs/HDFS-Slave2.E01` (3.2 GB), `inputs/HDFS-Slave2.E01.csv`, `inputs/HDFS-Slave2.E01.txt`, `inputs/README`, `inputs/index.md`, read-only at the kernel in every pane (`seatbelt`) |
| Flags | `--catalog --toolbox dfir --quarantine  --cap-per-agent 14 --allow-host isf-server.techanarchy.net --allow-tool-forging --cap-usd 80 --wall-clock 240` |
| Outcome | `work/report.md` under the required headings, `work/timeline.md` with 40 dated rows, ledger of 118 entries (65 events, 23 indicators, 30 findings); **7/7 checks** pass |
| Cost | **$29.57** of the $80.00 cap, 351 model calls, 23.8M tokens; $13.46 on grok-4.6, $16.11 on DeepSeek-V4-Pro |
| Harness | 414 shell writes taken as implicit claims, 0 claim violations, 9 forged tool(s) called 73 times, 2 forge hints, 6 idle nudges, 0 writes to `inputs/` |

## What we asked

[`goal.md`](goal.md) is the goal document as handed to the swarm. The questions, verbatim:

1. How did the threat actor gain access to each system? The service, the vulnerability or credential, the source address, the first evidence of the intrusion.
2. What privileges were obtained, and how (exploit, sudo, credentials, SUID, cron, misconfiguration)?
3. What modifications were applied to each system: files, packages, configurations, users, keys, binaries, logs cleared or altered.
4. What persistence mechanisms are in place: backdoors, users, SSH keys, cron, systemd units, init scripts, shells, sessions, kernel modules.
5. Could this system be cleaned or recovered, and what would it take?
6. Notes and recommendations, the full timeline of the intrusion, and anything else the examiner should know.

## What the agents did

Three disk images from one Hadoop cluster — a master and two slaves — and a
single question that spans them. 24 minutes, $29.57, all seven checks.

**The swarm mapped itself onto the evidence.** Nobody was assigned anything,
and within minutes the names on the board were `Master Investigator`, `Slave1
Investigator`, `Slave2 Investigator` and `Cross-Node IOC`: one agent per node,
one to carry indicators between them, and the rest on the deleted logs, the
timeline and the report. That is the division a seat list would have had to
guess in advance, and the swarm read it off the catalog in its first turns.

**What it found.** Initial access through the cluster's exposed service, then
`CVE-2017-16995` — the eBPF verifier flaw in the Linux kernel — for privilege
escalation, with persistence left behind as a PHP payload and a listening
`ncat`. The attacker wiped logs afterwards and edited `sshd_config`. The
cross-node seat is what made the story one story: the same indicators appear
on all three nodes at different times, and the report carries the access times
corrected to UTC so the order is not an artefact of three machines' clocks.

**What the harness did.** No cap steer, no harness fault, and the tool library
was called where it applied. Twenty-seven of the thirty tools carried in parse
Windows artefacts, so most sat unused again, which is the same honest result
the first Linux case gave: a library saves work between cases that rhyme, and
a Hadoop cluster does not rhyme with a Windows workstation.

The answers are in [`run/work/report.md`](run/work/report.md); the notes each seat kept are next to it under [`run/work/`](run/work/), the merged timeline is [`run/work/timeline.md`](run/work/timeline.md), and the ledger the timeline was built from is [`run/ledger.md`](run/ledger.md). The board is under [`run/board/`](run/board/), the raw trace is [`run/trace/events.jsonl`](run/trace/events.jsonl), and [`run/summary.md`](run/summary.md) is the summary `scripts/summary.ts` wrote.

## What the harness did, by the numbers

| Signal | Count |
| --- | --- |
| trace events | 1605 |
| bash calls | 239 |
| posts | 26 on 1 thread(s) |
| implicit claims (shell writes turned into claims) | 414 |
| claim violations | 0 |
| forge hints | 2 |
| forged tools | `hdfs_fls_grep` by s9a5f02 (0 calls), `hdfs_icat` by s9a5f02 (0 calls), `master_icat` by s9a5f06 (2 calls), `hdfs_grep` by s9a5f00 (0 calls), `hdfs_icat` by s9a5f01 (0 calls), `slave_icat` by s9a5f01 (0 calls), `slave1_icat` by s9a5f04 (0 calls), `hdfs_icat` by s9a5f03 (0 calls), `hdfs_node_icat` by s9a5f03 (19 calls) |
| idle nudges | 6 |
| sentinel nudge | reached 6, missed 0 |
| inputs checks | 4 |
| writes to inputs/ | 0 |
| per-agent cap steers / stops | 0 / 0 |
| ledger entries | 118 (65 events, 23 indicators, 30 findings) by 7 agents |

## What it cost, and who spent it

| Agent | Seat | Model | Spend | Calls | Tokens |
| --- | --- | --- | --- | --- | --- |
| s9a5f04 |  | DeepSeek-V4-Pro | $8.12 | 91 | 7.8M |
| s9a5f05 |  | DeepSeek-V4-Pro | $4.59 | 74 | 4.2M |
| s9a5f02 |  | grok-4.6 | $3.98 | 34 | 3.3M |
| s9a5f01 |  | grok-4.6 | $3.53 | 27 | 2.0M |
| s9a5f06 |  | DeepSeek-V4-Pro | $3.40 | 70 | 2.8M |
| s9a5f00 |  | grok-4.6 | $3.27 | 31 | 2.2M |
| s9a5f03 |  | grok-4.6 | $2.68 | 24 | 1.6M |

| Model | Spend | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| `azure-foundry/DeepSeek-V4-Pro` | $16.11 | 54 % | 235 | 3 |
| `azure-foundry/grok-4.6` | $13.46 | 46 % | 116 | 4 |

Each agent's terminal as it stood at the final round is under [`run/panes/`](run/panes/) — 7 panes, one per agent.

## Screenshots

- [`01-board.png`](screenshots/01-board.png) — the console after the run: one agent per cluster node, one carrying indicators between them, each under the name it chose.

## Reproducing it

Get the evidence from the source above into one directory, install `sleuthkit`, `libewf`, `yara` and `foremost` (brew) and `volatility3` (pipx), start Herdr, and run:

```
scripts/swarm.sh start --models "openai/gpt-5.4=4,deepseek/deepseek-v4-pro=3" --cap-usd 80 --wall-clock 240 \
  --goal-file goal.md --inputs <evidence dir> --inputs-max-mb 60000 --catalog --toolbox dfir --quarantine  --cap-per-agent 14 --allow-host isf-server.techanarchy.net --allow-tool-forging \
  --case-id AH-L02 --examiner "<name>"
```
