# Use cases

Real runs of the swarm on public forensic challenges, one folder each: what
was asked, who did what, what the harness did, what it cost, and everything
the agents wrote, with the console and the terminals captured while they
worked. The cases are Ali Hadi's Digital Forensic Challenge Images
(https://www.ashemery.com/dfir.html); the evidence files are not in this
repository. Every run: the dfir seat preset, the evidence catalog, the toolbox
check, the quarantine and the ledger. Team size and both caps are set per case
and each run's own summary carries them; the first runs took seven agents
under a $60 cap and a $12 per-agent cap, the later ones five to ten under caps
up to $110. The team is four `openai/gpt-5.4` and three
`deepseek/deepseek-v4-pro`, except the last four, which run on one Azure AI
Foundry resource and size the team to the case: the SysInternals case on four
`grok-4.6` and three `DeepSeek-V4-Pro`, the NTFS case on two and three, Encrypt
Them All on four and five because three encryption puzzles need more hands than
one, and Meeting Location on four and three. From Meeting Location onwards the
harness assigns nobody anything: the agents read the goal, divide the work
between them and say with `name()` what to call them and what they are taking
on.

| Case | Folder | Time | Cost | Checks | In one line |
| --- | --- | --- | --- | --- | --- |
| #1 Web Server (run 1) | [dfir-web-server-case](dfir-web-server-case/README.md) | 14.5 min | $7.98 | 9/9 | DVWA breached from 192.168.56.102 by SQL and command injection, two accounts added, five web shells and a reverse shell; the run that produced the improvement plan |
| #1 Web Server (run 4, on Linux) | [dfir-web-server-case/run-4-linux.md](dfir-web-server-case/run-4-linux.md) | 14.1 min | $4.81 | 6/9 | the first run on a Linux server: four agents on `gpt-5.4-mini`, 26 GB of evidence bound in place instead of copied, and nine defects the macOS runs and both CI tiers could not see — two of them security defects, all fixed |
| #1 Web Server (run 5, self-compaction) | [dfir-web-server-case/run-5-self-compact.md](dfir-web-server-case/run-5-self-compact.md) | 14.7 min | $2.92 | 3/9 | the first run where the agents compacted their own context: three hand-offs at 144k, 168k and 98k tokens with the notes returned verbatim and the work resumed; a pane hook defect that had stopped every agent before its first prompt, fixed; the swarm cut short by a slice-level `done` before the report was written |
| #1 Web Server (run 6, nothing cut) | [dfir-web-server-case/run-6-lossless.md](dfir-web-server-case/run-6-lossless.md) | 34.2 min | $4.55 | 9/9 | the first run with every tool output kept whole (eleven of them, 21 MB, under `tool-output/`, the largest a 12.7 MB grep the model saw 35 KB of), every summary written by `gpt-5.4-nano` for a cent each, four hand-offs all between the warning and the compact line, the report written and verified by peers; the venv taken for 642 claims and seven violations, fixed; the idle watchdog found dead a minute after the kickoff started it, cause unexplained, the kickoff now checks and restarts it |
| #1 Web Server (runs 2 and 3) | [dfir-web-server-case/run-2.md](dfir-web-server-case/run-2.md) | 18.0 / 17.9 min | $9.36 / $12.45 | 9/9 | the same case on the new harness: notices 40 → 1, idle agents 3 → 0, a ledger of 69 entries, `phpshell2.php` named as a Metasploit PHP meterpreter stager |
| #2 User Policy Violation | [dfir-c02-user-policy-violation](dfir-c02-user-policy-violation/README.md) | 10.0 min | $11.40 | 7/7 | data exfiltration by the only interactive user: a confidential PDF disguised as a picture, encrypted archives over Skype and Dropbox, a TeamViewer session granted to an outsider, anti-forensics tools afterwards |
| #3 Mystery Hacked System | [dfir-c03-mystery-hacked-system](dfir-c03-mystery-hacked-system/README.md) | 14.9 min | $16.00 | 7/7 | `Magnify.exe` replaced by `cmd.exe` (the login-screen backdoor), two taunt files, a VBoxService clock rollback resolved by `$LogFile` sequence numbers, an interpretation the swarm argued about and corrected |
| #4 Alternate Data Streams | [dfir-c04-alternate-data-streams](dfir-c04-alternate-data-streams/README.md) | 15.2 min | $12.45 | 7/7 | PuTTY hidden in two streams, two prefetch files hidden as streams on empty files, a Meterpreter reverse shell Defender detected and removed, a forged decompressor for Windows 10 prefetch |
| #5 BSides Amman 2021 | [dfir-c05-bsides-amman-2021](dfir-c05-bsides-amman-2021/README.md) | 15.3 min | $19.11 | 9/9 | sixteen workshop questions with the command and output for each; the confidential documents traced to `Joker` and a network share; `DCode.exe` run once under the name `dd.exe` |
| #6 Browser Policy Violation | [dfir-c06-browser-policy-violation](dfir-c06-browser-policy-violation/README.md) | 11.2 min | $10.03 | 7/7 | Chrome 70 brought in by VMware drag-and-drop and installed system-wide, used to administer a server through Webmin and to browse a drug storefront; nothing hidden |
| #7 SysInternals (on Azure) | [dfir-c07-sysinternals-azure](dfir-c07-sysinternals-azure/README.md) | 24.3 min | $37.03 | 7/7 | a fake SysInternals download whose XOR-encoded URL pulls a second stage that installs itself as `VMwareIOHelperService` and deletes Prefetch files in a loop; the first run on Azure AI Foundry, and the run where a correction after the sign-off never reached the report |

The DeepSeek figures are off-peak. Pi bills `deepseek/deepseek-v4-pro` at
DeepSeek's peak rate, and every run here started outside the peak window, so
the invoice is half of what the harness reported while it ran; each case
README carries the arithmetic. The Azure case bills at Azure's own rates,
which are not DeepSeek's.
| #8 NTFS Hidden Files (on Azure) | [dfir-c08-ntfs-hidden-files](dfir-c08-ntfs-hidden-files/README.md) | 39.7 min | $40.78 | 7/7 | five things hidden in the file system itself: a stream on a file, streams on two directories (one a ZIP calling itself a JPEG, holding the very tool that reveals streams), a hash in the slack of an `$MFT` record, and an unlinked `$Quota` with tampered flags that `chkdsk` had recovered |
| #9 Encrypt Them All (on Azure, 9 seats) | [dfir-c09-encrypt-them-all](dfir-c09-encrypt-them-all/README.md) | 92.9 min | $108.48 | 6/7, **no sentinel** | three encryption puzzles in one image: the AES password recovered from a Mattermost conversation in the browser cache, twin volumes named R2D2 of which only one is BitLocker encrypted, and a GPG key pair whose passphrase was not found; the run that showed the per-agent cap had never been armed |
| #10 Meeting Location (on Azure, nothing assigned) | [dfir-c10-meeting-location](dfir-c10-meeting-location/README.md) | 48.0 min | $81.76 | 7/7 | the first run where the harness handed out no work at all: seven agents named themselves in four minutes, eighteen tools from earlier runs were waiting and were called 141 times, and a wiped Kali virtual disk was carved back to read the guest's own logins; the meeting location itself is reported as unknown, with its two candidate routes marked as hypotheses |
| #11 Where Did the Administrator Go (on Azure) | [dfir-c11-administrator-files](dfir-c11-administrator-files/README.md) | 15.4 min | $22.76 | 7/7 | the run that forged nothing: twenty-one tools from earlier cases covered it, and the one tool an agent did write was never called. `SDelete64` renamed `dark_knight.c5w` destroyed the Administrator's files on 2024-07-27 and `wevtutil` cleared the logs after; the report says recovery is impossible, and why |
| Memory #1 RansomCare (on Azure) | [dfir-m01-ransomcare](dfir-m01-ransomcare/README.md) | 22.1 min | $27.47 | 7/7 | two memory dumps, no disk: the ransomware names itself Tocrypt in memory and was identified from process lists, command lines, injected regions and dumped strings. The run that found A26 — evidence arriving with the execute bit set made the inputs guard report the same two files 374 times without a single real change |
| Unallocated #1 Malware (on Azure) | [dfir-u01-unallocated-malware](dfir-u01-unallocated-malware/README.md) | 24.0 min | $23.38 | 7/7 | 24 GB of unallocated space and nothing else: no partition table, no file system, an empty catalog. The cleanest division of labour of any run — seven agents, seven jobs, no overlap — and the case where the tool library was worth almost nothing, because a carving case shares little with a file system case |
| Linux #1 Compromised Web Server (on Azure) | [dfir-l01-compromised-web-server](dfir-l01-compromised-web-server/README.md) | 27.4 min | $38.15 | 7/7 | the first non-Windows image in the set. Three of seven agents clustered on the web logs, then two of them moved themselves to the jobs the finish line needed — a report keeper and a citation critic — without anyone asking. The Windows-shaped half of the tool library was dead weight here |
| Linux #2 Compromised HDFS Cluster (on Azure) | [dfir-l02-hdfs-cluster](dfir-l02-hdfs-cluster/README.md) | 24.2 min | $29.57 | 7/7 | three images from one Hadoop cluster, and the swarm read the division off the catalog: one agent per node, one carrying indicators between them. `CVE-2017-16995` for privilege escalation, a PHP payload and a listening `ncat` for persistence, logs wiped and `sshd_config` edited after; the access times are corrected to UTC so the order across three machines is real |
| Linux #3 The Attacker's Kali System (on Azure) | [dfir-l03-attacker-kali](dfir-l03-attacker-kali/README.md) | 21.5 min | $23.72 | 7/7 | the last of the fifteen, and the only disk that belongs to the attacker: Metasploit's own session records, the loot kept in `/root`, the shares and the histories. One agent named itself `GapFill` and took whatever the others had not claimed — a job no preset would have thought to write |

## The series, end to end

Sixteen cases, nineteen published runs (the web server case was run three
times, on three versions of the harness), and one run stopped and not
published because a harness fault had left its agents without the harness's
own instructions.

| | |
| --- | --- |
| Cases | 16 of 16 answered. Seventeen runs certified at 7/7 or 9/9; Challenge 9 reached 6/7 and never wrote a sentinel, and the Linux re-run of the web server case reached its sentinel at 6/9. Both are published as they ended |
| Runs | 19 published, 1 stopped and documented as a fault |
| Spend | **$536.69** at the corrected rates, plus $25.68 on the stopped run |
| Work | 7,347 model calls, 643M tokens |
| Evidence | 137 GB of images, never modified: every run's inputs verified unchanged |

What the series changed in the harness is in
[docs/improvement-plan.md](../improvement-plan.md): twenty-six items under A,
fourteen under B, most of them shipped, each one traceable to the minute of the
run that produced it. The largest single change came from the operator rather
than from a run — the harness now assigns nobody any work at all, because the
only boundaries it should draw are the sandbox's own. The three runs after that
change divided the work by conversation, filled the report and critic jobs
without being told to, and in the Hadoop case mapped one agent to each cluster
node before anyone had described the cluster.

The costs are worth reading with the rate corrections in mind: DeepSeek's own
API bills by the hour of day, and Azure charges its own prices rather than the
model vendors'. Both are documented in
[docs/credentials-and-teams.md](../credentials-and-teams.md), and every case
README carries the arithmetic for its own run.

What the runs changed in the harness is in [docs/improvement-plan.md](../improvement-plan.md):
items A11 to A17 and B11 all came out of these cases, each fixed before the
next one ran. Running the seventh on a different pair of models needed one
more change — a provider defined in Pi's `models.json` now brings its own
host to the netguard allowlist — and produced three more observations
(duplicate forges, the shared extraction root, and a sign-off that a later
correction should have invalidated).

A report in these folders is what the swarm wrote, not what a human
verified afterwards. Where a run's own board contradicts its report, the
case README says so.

## Another series: BelkaCTF

[belkactf/](belkactf/README.md) holds the second source of cases: Belkasoft's
capture-the-flag editions, seven of them since 2021, each one a published
image with a fixed set of questions. The first of them has been run:

| Case | Folder | Time | Cost | Checks | In one line |
| --- | --- | --- | --- | --- | --- |
| BelkaCTF #6 Bogus Bill | [belkactf/belkactf6-bogus-bill](belkactf/belkactf6-bogus-bill/README.md) | 50.5 min | $77.32 | 10/10 | the first CTF and the first ten-agent run, on five models across four providers and one of them local; the swarm found the BitLocker container hidden in an alternate data stream, recovered its recovery key from a note inside an iTunes backup, wrote its own unlocker because the host had none, and still could not open it — and answered the hardest question of the event anyway |

Their folders are laid out like the ones below, with one rule of their own:
the official write-ups stay out of this repository, so a run cannot read the
answer off the disk it is running from. A CTF is scored by string comparison
rather than by whether a report holds together, which makes these the first
cases where a run can be marked rather than only read.

## How a folder is laid out

- `README.md`: the header table (run, team, evidence, flags, outcome, cost, harness signals), the questions verbatim, what the agents did minute by minute, the harness's numbers, the cost by agent and by model, the screenshots, and how to reproduce it.
- `goal.md`: the goal document handed to the swarm.
- `run/`: what `swarm.sh package` wrote — `work/report.md` and the seats' notes, `work/timeline.md`, `ledger.md` and `ledger.jsonl`, `summary.md` from `scripts/summary.ts`, the board, the trace, the catalog index, the toolbox, the inputs manifest with hashes, `MANIFEST.txt` with a hash per file — plus the idle-watchdog log and every pane's terminal at the end under `run/panes/`.
- `screenshots/`: the console during the run.
