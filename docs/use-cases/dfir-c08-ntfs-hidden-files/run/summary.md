# Run summary: sfcc3 — Challenge 8: NTFS hidden files (Azure)

- State: done · sentinel present
- Started: 2026-09-18T15:17:52Z · Duration: 39m 44s (to the sentinel at 2026-09-18T15:57:35.534Z)
- Case: AH-C08 · Examiner: Halil Ozturkci
- Kickoff: model 2xazure-foundry/grok-4.6 + 3xazure-foundry/DeepSeek-V4-Pro · catalog · toolbox dfir · quarantine · allow-host isf-server.techanarchy.net
- Sandbox: `/Users/halilozturkci/DFIR/SampleCases/AliHadi-swarm/sfcc3`

## Outcome

Sentinel `done/SWARM_DONE` by **sfcc303** at 2026-09-18T15:57:35.534Z: All 5 hidden items identified, timeline built (28 rows, 28 events), report assembled with all 6 sections, critic sign-off posted, inputs verified unchanged. Swarm definition of done met. (output: `work/report.md`)

| Agent | Marker | At | Reason |
| --- | --- | --- | --- |
| sfcc300 | — |  |  |
| sfcc301 | done | 2026-09-18T15:58:04.893Z | sentinel_present |
| sfcc302 | — |  |  |
| sfcc303 | done | 2026-09-18T15:57:35.534Z | All 5 hidden items identified, timeline built (28 rows, 28 events), report assembled with all 6 sections, critic sign-off posted, inputs verified unchanged. Swarm definition of done met. |
| sfcc304 | done | 2026-09-18T15:58:02.355Z | Swarm complete. All 5 hidden items identified and documented in work/report.md. All DoD checks met. Sign-off posted as critic/editor. |

3 of 5 agents marked; without a marker: sfcc300, sfcc302.

## Team

| Agent | Role | Model | Seat | Spent | Calls | Tokens |
| --- | --- | --- | --- | --- | --- | --- |
| sfcc300 | worker | azure-foundry/grok-4.6 | Disk and file system: partitions, $MFT, every file and stream the catalog lists, deleted and unallocated content; owns `work/disk.md`. | $5.63 | 31 | 2,890,630 |
| sfcc301 | worker | azure-foundry/grok-4.6 | Artifacts and execution: registry hives, event logs, prefetch, LNK, jump lists, shimcache, amcache, browser and application traces; owns `work/artifacts.md`. | $6.70 | 41 | 3,647,127 |
| sfcc302 | worker | azure-foundry/DeepSeek-V4-Pro | Recovery and analysis: carving, decoding, hashing and reading whatever the other seats pull out, with strings and parsers; owns `work/analysis.md`. | $9.41 | 73 | 7,683,173 |
| sfcc303 | worker | azure-foundry/DeepSeek-V4-Pro | Timeline and ledger: records every dated event peers report with `record kind=event` and writes `work/timeline.md` from `ledger/ledger.md`. | $9.53 | 68 | 7,471,815 |
| sfcc304 | worker | azure-foundry/DeepSeek-V4-Pro | Critic and editor: verifies every citation, challenges weak claims on the board, assembles `work/report.md` and posts the sign-off. | $9.52 | 75 | 7,043,178 |

By model:

| Model | Spent | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| azure-foundry/DeepSeek-V4-Pro | $28.45 | 70% | 216 | 3 (sfcc302, sfcc303, sfcc304) |
| azure-foundry/grok-4.6 | $12.33 | 30% | 72 | 2 (sfcc300, sfcc301) |

Spent $40.78 of a $60.00 cap, $12.00 per agent; 288 provider calls, 28,735,923 tokens.

## Activity

823 trace events from 2026-09-18T15:17:57.428Z to 2026-09-18T15:58:15.963Z.

| Agent | Events | Top tools |
| --- | --- | --- |
| sfcc304 | 212 | bash 74, thinking 73, read 12, record 12, make_tool 4 |
| sfcc302 | 205 | bash 77, thinking 65, claim_file 23, read 9, wait 5 |
| sfcc303 | 192 | thinking 66, bash 46, record 23, wait 13, read 11 |
| sfcc300 | 112 | bash 29, claim_file 26, record 13, read 11, post 5 |
| sfcc301 | 98 | bash 25, claim_file 16, read 13, wait 9, record 7 |
| system | 4 | idle_nudge 4 |

| Signal | Count |
| --- | --- |
| claim violations | 0 |
| implicit claims (shell writes turned into claims) | 63 |
| inputs violations | 0 |
| inputs checks | 3 |
| forge hints | 6 |
| sentinel nudges | 1 |
| idle nudges | 4 |
| per-agent cap steers | 0 |
| per-agent cap stops | 0 |
| posts | 23 |
| bash calls | 251 |

Forged tools:

- `extract_stream` by sfcc303 at 2026-09-18T15:28:35.375Z (bash; called 0 times)
- `check_inputs` by sfcc304 at 2026-09-18T15:41:47.090Z (bash; called 5 times)

Bash leading commands (top 10):

| Command | Runs |
| --- | --- |
| `icat` | 45 |
| `python3` | 39 |
| `grep` | 23 |
| `fls` | 15 |
| `echo` | 14 |
| `ls` | 12 |
| `istat` | 11 |
| `cat` | 10 |
| `mkdir` | 4 |
| `for` | 3 |

## Ledger

58 entries: 28 events, 19 indicators, 11 findings (`ledger/ledger.md`).

Last 10 events in time order:

| Time (UTC) | Event | Source | By |
| --- | --- | --- | --- |
| 2023-03-19T23:01:03.000Z | Photos directory created with alternate data stream flag1.jpg (15282 bytes, JPEG image 434x232) — ADS on a directory | $STANDARD_INFORMATION attribute, inode 169 | sfcc304 |
| 2023-03-19T23:01:03.000Z | Directory Photos created and flag1.jpg ADS attached | istat inode 169 | sfcc300 |
| 2023-03-19T23:03:36.000Z | flag2.jpg (71,266 bytes) created as Alternate Data Stream on directory Documents/Work/2023/Tools (inode 170) | catalog/NTFS-HiddenFiles.E01/p0/timeline.csv and bodyfile.txt | sfcc303 |
| 2023-03-19T23:03:36.000Z | Tools directory created with alternate data stream flag2.jpg (71266 bytes, ZIP archive containing AlternateStreamView.exe) — ADS on a directory with binary obfuscation | $STANDARD_INFORMATION attribute, inode 170 | sfcc304 |
| 2023-03-19T23:03:36.000Z | Directory Tools created and flag2.jpg ADS (ZIP) attached | istat inode 170 | sfcc300 |
| 2023-03-19T23:26:32.000Z | WelcomeBack.txt (1,011 bytes) created at Documents/Personal/2023/ (inode 171) | catalog/NTFS-HiddenFiles.E01/p0/timeline.csv and bodyfile.txt | sfcc303 |
| 2023-03-19T23:26:32.000Z | WelcomeBack.txt created with $DATA at attribute ID 128-3 (unusual) containing ChatGPT welcome letter (1011 bytes); MD5 hash of flag2.jpg hidden in MFT entry slack space at bytes 404-510 | $STANDARD_INFORMATION attribute, inode 171; raw MFT entry analysis | sfcc304 |
| 2023-03-19T23:26:32.000Z | WelcomeBack.txt written into reused MFT record 171 (sequence 2), leaving prior UTF-16 hash in unused record bytes | istat inode 171; $MFT record 171 | sfcc300 |
| 2023-03-20T00:13:35.000Z | Mass access event: all user directories and hidden ADS files accessed (last access time updated on all Documents/* directories and flag1.jpg/flag2.jpg ADS streams) | catalog/NTFS-HiddenFiles.E01/p0/timeline.csv | sfcc303 |
| 2023-03-20T03:20:57.000Z | Forensic acquisition of NTFS volume using FTK Imager 4.7.1.2. Image MD5 e7d5b36a407d5a02d0872d4dd3f3f9d0, SHA1 5edc4c6efda9d266ecabcab5629694d0063e9d7f | inputs/NTFS-HiddenFiles.E01.txt | sfcc303 |

## Work

| File | Size |
| --- | --- |
| `work/analysis.md` | 10.8 KB |
| `work/artifacts.md` | 11.7 KB |
| `work/disk.md` | 10.0 KB |
| `work/report.md` | 11.9 KB |
| `work/timeline.md` | 7.0 KB |
| `work/extracted/Photos_flag1.jpg` | 14.9 KB |
| `work/extracted/Quota.bin` | 4.0 KB |
| `work/extracted/Quota.slack` | 0 B |
| `work/extracted/README.txt` | 15 B |
| `work/extracted/README.txt_Secrets.txt` | 154 B |
| `work/extracted/Secrets.txt` | 154 B |
| `work/extracted/Tools_flag2.jpg` | 69.6 KB |
| `work/extracted/WelcomeBack.slack` | 3.0 KB |
| `work/extracted/WelcomeBack.txt` | 1011 B |
| `work/extracted/chkdsk18.log` | 8.0 KB |
| `work/extracted/chkdsk19.log` | 7.0 KB |
| `work/extracted/flag1.jpg` | 14.9 KB |
| `work/extracted/flag1.slack` | 1.1 KB |
| `work/extracted/flag2.jpg` | 69.6 KB |
| `work/extracted/flag2.slack` | 2.4 KB |
| `work/extracted/flag2_contents/AlternateStreamView.chm` | 16.0 KB |
| `work/extracted/flag2_contents/AlternateStreamView.exe` | 112.8 KB |
| `work/extracted/flag2_contents/readme.txt` | 11.3 KB |
| `work/extracted/flag2zip/AlternateStreamView.chm` | 16.0 KB |
| `work/extracted/flag2zip/AlternateStreamView.exe` | 112.8 KB |
| `work/extracted/flag2zip/readme.txt` | 11.3 KB |
| `work/extracted/quota_decrypted.bin` | 1.7 KB |
| `work/extracted/quota_encrypted.bin` | 1.7 KB |
| `work/extracted/quota_raw.bin` | 4.0 KB |
| `work/sfcc300/` (scratch of sfcc300) | 1 files, 256.0 KB |
| `work/sfcc301/` (scratch of sfcc301) | 15 files, 91.7 MB |
| `work/sfcc302/` (scratch of sfcc302) | 0 files, 0 B |

## Custody

Inputs from `/Users/halilozturkci/DFIR/SampleCases/AliHadi/challenge-08-ntfs-hidden-files`, copied 2026-09-18T15:17:51Z: 3 files, 464.2 KB; enforcement asked auto, kickoff guard seatbelt.

| Input | Bytes | SHA-256 |
| --- | --- | --- |
| `inputs/CASE.md` | 653 | `2b30af4bc493bfea15d606a8fe20eea44bdddd57be05a95b132067662c48046a` |
| `inputs/NTFS-HiddenFiles.E01` | 473,520 | `0f043bb8da0efdbd750a5127e1d9ff194b2a4116f8dd38cf8029d46710bb5ddd` |
| `inputs/NTFS-HiddenFiles.E01.txt` | 1,139 | `f23ac5f0611de252af83f131b381de35c32b7b503bce02bfae4df398a619c023` |

| Inputs check | By | Result |
| --- | --- | --- |
| 2026-09-18T15:57:35.534Z | sfcc303 | intact: 3 checked, 0 modified, 0 missing, 0 added |
| 2026-09-18T15:57:42.778Z | sfcc304 | intact: 3 checked, 0 modified, 0 missing, 0 added |
| 2026-09-18T15:58:02.355Z | sfcc304 | intact: 3 checked, 0 modified, 0 missing, 0 added |

Toolbox (dfir): 12 present — mmls (The Sleuth Kit ver 4.15.0), fls (The Sleuth Kit ver 4.15.0), icat (The Sleuth Kit ver 4.15.0), mactime (The Sleuth Kit ver 4.15.0), vol (Volatility 3 Framework 2.28.2), regipy-dump (6.3.0), evtx_dump (python-evtx ok), yara (4.5.8), exiftool (12.92), sqlite3 (3.54.0 2026-04-09 12:25:13 8fa8248e303219400c646a885e36dfc52eae33d83f4412e3f369b2be5373aapl (64-bit)), strings (error: /Library/Developer/CommandLineTools/usr/bin/strings: unknown flag: --version), python3 (Python 3.12.1); 0 missing.

Evidence catalog: 1 disk image(s), 0 memory image(s), 5 catalog file(s).
