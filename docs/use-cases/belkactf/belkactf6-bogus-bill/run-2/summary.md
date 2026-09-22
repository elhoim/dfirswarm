# Run summary: s83fd — belkactf6-rerun

- State: done · sentinel present
- Started: 2026-09-21T11:06:35Z · Duration: 1h 0m (to the sentinel at 2026-09-21T12:06:39.499Z)
- Kickoff: model 3xazure-foundry/grok-4.6 + 4xazure-foundry/DeepSeek-V4-Pro + 2xopenai/gpt-5.4 + 1xlmstudio/qwen3.8-27b-uncensored · catalog · toolbox dfir · quarantine · allow-host api.wigle.net,wigle.net,nominatim.openstreetmap.org
- Sandbox: `/Users/halilozturkci/DFIR/SwarmRuns/s83fd`

## Outcome

Sentinel `done/SWARM_DONE` by **s83fd07** at 2026-09-21T12:06:39.499Z: cannot_complete (output: `work/report.md`)

| Agent | Marker | At | Reason |
| --- | --- | --- | --- |
| s83fd00 | done | 2026-09-21T12:08:16.551Z | sentinel_present |
| s83fd01 | done | 2026-09-21T12:07:26.864Z | sentinel_present |
| s83fd02 | done | 2026-09-21T12:08:03.140Z | sentinel_present |
| s83fd03 | done | 2026-09-21T12:07:04.003Z | sentinel_present |
| s83fd04 | done | 2026-09-21T12:07:04.311Z | SWARM_DONE sentinel exists. Completed iPhone Telegram deep analysis: confirmed Q3 shady accounts (@JesusStreeton1999, @Sm00thOperat0r, @locknload771, @diddyflowers), extracted chat evidence for Q7 (celebration), Q11 (Drew designer), Q16 (Chase insider), Q15 (ATM testing), Q17 (Panama offshore), Q13 (printing bot), Q14 (materials list). Recorded Apple ID finding in ledger. |
| s83fd05 | done | 2026-09-21T12:07:06.178Z | Swarm complete. Successfully contributed: unlocked BitLocker vault.vhdx using recovery key, extracted and analyzed Spending.xlsx (Q18), identified Rolex Submariner Date ref 126619LB (Q9), Xerox Phaser 7760DN printer (Q14), Laari Adda celebration venue (Q7), and updated flags.md with vault-derived answers. Full evidence cataloged in ledger. |
| s83fd06 | done | 2026-09-21T12:07:03.434Z | sentinel_present |
| s83fd07 | done | 2026-09-21T12:06:39.499Z | cannot_complete |
| s83fd08 | done | 2026-09-21T12:06:40.982Z | cannot_complete |
| s83fd09 | done | 2026-09-21T12:07:43.864Z | sentinel_present |

10 of 10 agents marked.

## Team

| Agent | Calls itself | Role | Model | Spent | Calls | Tokens |
| --- | --- | --- | --- | --- | --- | --- |
| s83fd00 | vault-unlock — Find the BitLocker passphrase/recovery key for vault.vhdx; extract Element EventStore and screenshots; fill Q6/Q9/Q15/Q17/Q18 once the vault opens | worker | azure-foundry/grok-4.6 | $9.03 | 40 | 4,515,079 |
| s83fd01 | vault-print — Q5/Q8 from catalog (phorger, Documents ADS vault.vhdx); pick up dropped print-ops Q11–Q16 and extract vault ADS, Capture.png, printer/Element artefacts into work/extracted/s83fd01/. | worker | azure-foundry/grok-4.6 | $6.78 | 38 | 3,369,802 |
| s83fd02 | chat-evidence — Mining iPhone Telegram strings plus Capture2.png for Q7/Q11–Q16/Q17, then filling flags.md with cited answers while others hunt the BitLocker key | worker | azure-foundry/grok-4.6 | $8.85 | 43 | 4,619,302 |
| s83fd03 | Key & Printer Hunter — Hunting BitLocker recovery key to unblock vault (enables Q6/Q9/Q15/Q17/Q18). Extracting Q14 printer model from NTUSER.DAT/SOFTWARE registry. Searching iPhone Telegram DB for key phrases. | worker | azure-foundry/DeepSeek-V4-Pro | $7.51 | 223 | 7,904,893 |
| s83fd04 | Chat & Timeline Analyst — Deep Telegram postbox DB analysis for BitLocker key, Q3 shady accounts, Q7 celebration, Q9 luxury, Q10 concert. Also extracting iPhone notes/other DBs that may hold the recovery key. | worker | azure-foundry/DeepSeek-V4-Pro | $3.22 | 111 | 3,556,969 |
| s83fd05 | Evidence Miner — Answering remaining Q7-Q16 from extracted evidence while vault decryption is attempted by others. Focusing on: Drew surname (Q11), LAARI ADA coords (Q7), printer model (Q14), validator leaker (Q16), CRBK SWIFT (Q17), concert (Q10), luxury item (Q9) | worker | azure-foundry/DeepSeek-V4-Pro | $12.72 | 302 | 16,930,471 |
| s83fd06 | Vault & Chat Analyst — Finding BitLocker key to unlock vault.vhdx (blocks Q6/Q9/Q15/Q17/Q18), plus Q7/Q10 from laptop chats | worker | azure-foundry/DeepSeek-V4-Pro | $1.57 | 68 | 1,546,579 |
| s83fd07 | vault-corroboration — Yielding primary vault-unlock hunting to s83fd00/s83fd06/s83fd04; I’ll stay on corroboration, citation cleanup, and downstream report/ledger support for the vault-related answers as new evidence lands. | worker | openai/gpt-5.4 | $12.07 | 208 | 37,521,923 |
| s83fd08 | iphone-lead — Pivoting from Q1-Q4 extraction to shared artifact rescue: taking work/dependencies.md and bootstrapping report/flags with Q1-Q4 because the prior owners rate-limited out and those files are still missing. | worker | openai/gpt-5.4 | $7.15 | 184 | 21,988,398 |
| s83fd09 | timeline-keeper — Maintaining work/timeline.md + work/dependencies.md from the ledger (both orphaned when s83fd03/s83fd06 rate-limited out), and owning Q7 (March celebration venue) + Q12 (makeshift lab address) from chat/calendar/laptop artefacts. | worker | lmstudio/qwen3.8-27b-uncensored | $0.00 | 23 | 874,725 |

By model:

| Model | Spent | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| azure-foundry/DeepSeek-V4-Pro | $25.01 | 36% | 704 | 4 (s83fd03, s83fd04, s83fd05, s83fd06) |
| azure-foundry/grok-4.6 | $24.66 | 36% | 121 | 3 (s83fd00, s83fd01, s83fd02) |
| openai/gpt-5.4 | $19.22 | 28% | 392 | 2 (s83fd07, s83fd08) |
| lmstudio/qwen3.8-27b-uncensored | $0.00 | 0% | 23 | 1 (s83fd09) |

Spent $68.89 of a $100.00 cap, $15.00 per agent; 1240 provider calls, 102,828,141 tokens; stop reason wall_clock.

## Activity

2339 trace events from 2026-09-21T11:06:47.204Z to 2026-09-21T12:08:16.661Z.

| Agent | Events | Top tools |
| --- | --- | --- |
| s83fd07 | 426 | claim_file 90, bash 76, thinking 68, wait 46, inbox 43 |
| s83fd05 | 423 | bash 223, thinking 123, claim_file 20, name 10, inbox 8 |
| s83fd08 | 318 | wait 59, thinking 51, inbox 49, bash 48, claim_file 23 |
| s83fd03 | 284 | bash 127, thinking 84, claim_file 20, inbox 12, text_search 10 |
| s83fd04 | 227 | bash 116, thinking 59, claim_file 17, inbox 7, read 7 |
| s83fd02 | 173 | bash 56, claim_file 55, read 24, name 6, text_search 6 |
| s83fd00 | 165 | claim_file 75, bash 41, read 21, inbox 4, name 4 |
| s83fd06 | 128 | bash 66, thinking 30, claim_file 9, read 5, name 4 |
| s83fd01 | 106 | bash 38, claim_file 26, read 7, name 6, record 6 |
| s83fd09 | 55 | thinking 19, bash 8, read 7, agent_error 2, agent_stop 2 |
| system | 34 | idle_nudge 34 |

| Signal | Count |
| --- | --- |
| claim violations | 3 |
| implicit claims (shell writes turned into claims) | 317 |
| inputs violations | 0 |
| inputs checks | 4 |
| forge hints | 9 |
| sentinel nudges | 1 |
| idle nudges | 34 |
| per-agent cap steers | 0 |
| per-agent cap stops | 0 |
| posts | 44 |
| bash calls | 799 |

Forged tools:

- `text_search` by s83fd02 at 2026-09-21T11:24:34.814Z (python3; called 22 times)
- `timeline_render` by s83fd09 at 2026-09-21T11:45:34.745Z (python3; called 0 times)

Bash leading commands (top 10):

| Command | Runs |
| --- | --- |
| `grep` | 132 |
| `sqlite3` | 73 |
| `python3` | 54 |
| `tar` | 45 |
| `strings` | 38 |
| `ls` | 30 |
| `icat` | 26 |
| `echo` | 22 |
| `mkdir` | 17 |
| `rg` | 15 |

## Ledger

47 entries: 23 events, 4 indicators, 20 findings (`ledger/ledger.md`).

Last 10 events in time order:

| Time (UTC) | Event | Source | By |
| --- | --- | --- | --- |
| 2024-01-15T13:01:03.000Z | The user opened file Y:\776AR-04U.PDF from the mounted Vault volume. | work/extracted/s83fd07/firefox_places.sqlite | s83fd07 |
| 2024-01-15T13:13:26.000Z | The user opened file Y:\B500 ATM Technical Documentation.pdf from the mounted Vault volume. | work/extracted/s83fd07/firefox_places.sqlite | s83fd07 |
| 2024-02-02T22:55:16.090Z | BitLocker Management later logged protector {a72eb768-e5f3-4df8-ad44-7445e81017aa} again for volume Y:. | work/s83fd07/bitlocker_events.xml | s83fd08 |
| 2024-03-23T00:00:00.000Z | Phorger's offshore statement records a $357 transaction at Laari Adda, consistent with the gang's March celebration venue. | work/s83fd07/vaultcheck/Spending.xlsx | s83fd07 |
| 2024-03-26T00:00:00.000Z | Phorger's offshore statement screenshot shows AIRBNB 14158B00005959 charged -47.3 PAB on 26 Mar 2024 | work/extracted/s83fd02/Capture2.png | s83fd02 |
| 2024-03-26T00:00:00.000Z | Phorger's offshore PAB account shows AIRBNB 14158B00005959 charge of -47.3 PAB. | work/extracted/s83fd01/Capture2.png | s83fd01 |
| 2024-03-27T00:00:00.000Z | Phorger's offshore statement screenshot shows LAARI ADA St. Louis charged -33.25 PAB on 27 Mar 2024 | work/extracted/s83fd02/Capture2.png | s83fd02 |
| 2024-03-27T00:00:00.000Z | Phorger's offshore PAB account shows LAARI ADA St. Louis charge of -33.25 PAB. | work/extracted/s83fd01/Capture2.png | s83fd01 |
| 2024-04-03T23:33:26.000Z | The iPhone routined cache last detection time for the residence candidate at 25.088760966797,55.147160562762 was updated on the device. | work/extracted/s83fd08/private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite | s83fd08 |
| 2024-12-24T22:57:50.227Z | BitLocker Management again logged protector {a72eb768-e5f3-4df8-ad44-7445e81017aa} for volume Y:, indicating later reuse of the encrypted volume. | work/s83fd07/bitlocker_events.xml | s83fd08 |

## Work

| File | Size |
| --- | --- |
| `work/dependencies.md` | 2.8 KB |
| `work/flags.md` | 2.7 KB |
| `work/report.md` | 14.0 KB |
| `work/timeline.md` | 4.9 KB |
| `work/.tmp/jiti/extensions-agent-swarm.2cd9966e.mjs` | 97.7 KB |
| `work/.tmp/jiti/extensions-herdr-agent-state.1816956d.mjs` | 6.1 KB |
| `work/.tmp/jiti/extensions-playwright-tool.42f9ed12.mjs` | 10.8 KB |
| `work/.tmp/jiti/extensions-protocol.d01bfce7.mjs` | 151.0 KB |
| `work/.tmp/jiti/extensions-toolchain.e7bf3ef4.mjs` | 4.7 KB |
| `work/.tmp/pi-bash-4e98aa6c8740d6b1.log` | 213.1 KB |
| `work/.tmp/pi-bash-523c740455a978a5.log` | 107.5 KB |
| `work/.tmp/pi-bash-68a6e4591098e601.log` | 51.7 KB |
| `work/.toolchain/.cache/fontconfig/533634856807bec89d8faaf514cbc764-le64.cache-12` | 219.7 KB |
| `work/.toolchain/.cache/fontconfig/CACHEDIR.TAG` | 200 B |
| `work/.toolchain/.cache/gitstatus/gitstatusd-darwin-arm64` | 2.0 MB |
| `work/.toolchain/.cache/p10k-dump-halilozturkci.zsh` | 127.7 KB |
| `work/.toolchain/.cache/p10k-dump-halilozturkci.zsh.zwc` | 288.4 KB |
| `work/.toolchain/.cache/p10k-halilozturkci/prompt-41` | 22.3 KB |
| `work/.toolchain/.cache/p10k-instant-prompt-halilozturkci.zsh` | 20.7 KB |
| `work/.toolchain/.cache/p10k-instant-prompt-halilozturkci.zsh.zwc` | 53.9 KB |
| `work/.toolchain/.cache/pip/http/3/9/f/5/4/39f542c6e9bf6e28c13ff38ce74eccee4160e51bb46155f1c8c39c5e` | 465.6 KB |
| `work/.toolchain/.cache/pip/http/4/0/5/1/4/405142f74e02a2cd64981dafdf33ddc6f302a096f357f8c35c8216b4` | 545.0 KB |
| `work/.toolchain/.cache/pip/http/4/e/8/4/7/4e847ec95ebf92688195afdb13b4ffb4e6f9d4e3eafac2f2bd857975` | 2.9 KB |
| `work/.toolchain/.cache/pip/http/5/4/a/9/1/54a91633e5442f37f4ad463ffb968c236c3d9d132decba10e86d9883` | 2.4 KB |
| `work/.toolchain/.cache/pip/http/b/8/9/5/e/b895ecccf0ff8cf13840fab353ace6625bd0fb15a107985e4b7e39ca` | 22.8 KB |
| `work/.toolchain/.cache/pip/http/b/e/3/8/5/be3851d93af3a708eff996363dbbd3aab8094694dd7c30af83a8904a` | 25.9 KB |
| `work/.toolchain/lib/python/site-packages/__pycache__/_build.cpython-312.pyc` | 12.9 KB |
| `work/.toolchain/lib/python/site-packages/_build.py` | 9.6 KB |
| `work/.toolchain/lib/python/site-packages/libbde_python-20260916.dist-info/INSTALLER` | 4 B |
| `work/.toolchain/lib/python/site-packages/libbde_python-20260916.dist-info/METADATA` | 1.7 KB |
| `work/.toolchain/lib/python/site-packages/libbde_python-20260916.dist-info/RECORD` | 948 B |
| `work/.toolchain/lib/python/site-packages/libbde_python-20260916.dist-info/REQUESTED` | 0 B |
| `work/.toolchain/lib/python/site-packages/libbde_python-20260916.dist-info/WHEEL` | 136 B |
| `work/.toolchain/lib/python/site-packages/libbde_python-20260916.dist-info/licenses/COPYING` | 34.3 KB |
| `work/.toolchain/lib/python/site-packages/libbde_python-20260916.dist-info/licenses/COPYING.LESSER` | 7.5 KB |
| `work/.toolchain/lib/python/site-packages/libbde_python-20260916.dist-info/top_level.txt` | 13 B |
| `work/.toolchain/lib/python/site-packages/libvhdi_python-20260901.dist-info/INSTALLER` | 4 B |
| `work/.toolchain/lib/python/site-packages/libvhdi_python-20260901.dist-info/METADATA` | 1.2 KB |
| `work/.toolchain/lib/python/site-packages/libvhdi_python-20260901.dist-info/RECORD` | 957 B |
| `work/.toolchain/lib/python/site-packages/libvhdi_python-20260901.dist-info/REQUESTED` | 0 B |
| `work/.toolchain/lib/python/site-packages/libvhdi_python-20260901.dist-info/WHEEL` | 136 B |
| `work/.toolchain/lib/python/site-packages/libvhdi_python-20260901.dist-info/licenses/COPYING` | 34.3 KB |
| `work/.toolchain/lib/python/site-packages/libvhdi_python-20260901.dist-info/licenses/COPYING.LESSER` | 7.5 KB |
| `work/.toolchain/lib/python/site-packages/libvhdi_python-20260901.dist-info/top_level.txt` | 14 B |
| `work/.toolchain/lib/python/site-packages/pybde.cpython-312-darwin.so` | 1.4 MB |
| `work/.toolchain/lib/python/site-packages/pyvhdi.cpython-312-darwin.so` | 1.1 MB |
| `work/extracted/s83fd00/heicjpg/IMG_0003.jpg` | 1.4 MB |
| `work/extracted/s83fd00/heicjpg/IMG_0012.jpg` | 3.6 MB |
| `work/extracted/s83fd00/heicjpg/IMG_0026.jpg` | 1.5 MB |
| `work/extracted/s83fd00/heicjpg/IMG_0036.jpg` | 1018.4 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Containers/Shared/AppGroup/AF67BA79-B4B6-4F89-AD78-9054620F3322/NoteStore.sqlite` | 300.0 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Library/Calendar/Calendar.sqlitedb` | 944.0 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Library/Calendar/Calendar.sqlitedb-shm` | 32.0 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Library/Calendar/Calendar.sqlitedb-wal` | 0 B |
| `work/extracted/s83fd00/iphone/private/var/mobile/Library/Notes/notes.sqlite` | 140.0 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Library/Notes/notes.sqlite-shm` | 32.0 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Library/Notes/notes.sqlite-wal` | 0 B |
| `work/extracted/s83fd00/iphone/private/var/mobile/Library/SMS/sms.db` | 288.0 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Library/SMS/sms.db-shm` | 32.0 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Library/SMS/sms.db-wal` | 0 B |
| `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0002.PNG` | 548.9 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0003.HEIC` | 681.4 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0008.PNG` | 1.0 MB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0009.JPG` | 35.7 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0010.JPG` | 34.1 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0011.PNG` | 1.9 MB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0012.HEIC` | 2.1 MB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0026.HEIC` | 681.7 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0027.JPG` | 28.8 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0028.JPG` | 24.0 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0029.WEBP` | 71.4 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0030.WEBP` | 71.4 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0032.PNG` | 85.5 KB |
| `work/extracted/s83fd00/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0036.HEIC` | 433.8 KB |
| `work/extracted/s83fd00/temp1.png` | 120 B |
| `work/extracted/s83fd00/temp2.png` | 120 B |
| `work/extracted/s83fd00/vault/1.psd` | 84.4 MB |
| `work/extracted/s83fd00/vault/776AR-04U.PDF` | 378.9 KB |
| `work/extracted/s83fd00/vault/B500.txt` | 11.0 KB |
| `work/extracted/s83fd00/vault/B500_ATM.pdf` | 9.2 MB |
| `work/extracted/s83fd00/vault/Detailed_specification_for_Laser_Printer-Color.pdf` | 55.3 KB |
| `work/extracted/s83fd00/vault/Spending.xlsx` | 7.0 KB |
| `work/extracted/s83fd00/vault/b500p-1.png` | 634.9 KB |
| `work/extracted/s83fd00/vault/b500p-2.png` | 549.6 KB |
| `work/extracted/s83fd00/vault/b500p-3.png` | 507.8 KB |
| `work/extracted/s83fd00/vault/b500p-4.png` | 292.3 KB |
| `work/extracted/s83fd00/vault/b500p-5.png` | 578.7 KB |
| `work/extracted/s83fd00/vault/b500p-6.png` | 364.1 KB |
| `work/extracted/s83fd00/vault/b500p-7.png` | 342.6 KB |
| `work/extracted/s83fd00/vault/b500p-8.png` | 36.5 KB |
| `work/extracted/s83fd00/vault/bot.py` | 7.2 KB |
| `work/extracted/s83fd00/vault/inode_54.bin` | 2.0 MB |
| `work/extracted/s83fd00/vault/inode_55.bin` | 3.4 MB |
| `work/extracted/s83fd00/vault/inode_63.bin` | 3.7 MB |
| `work/extracted/s83fd00/vault/inode_65.bin` | 1.5 MB |
| `work/extracted/s83fd00/vault/inode_66.bin` | 1.5 MB |
| `work/extracted/s83fd00/vault/inode_68.bin` | 2.8 MB |
| `work/extracted/s83fd00/vault/inode_69.bin` | 3.4 MB |
| `work/extracted/s83fd00/vault/inode_70.bin` | 371.4 KB |
| `work/extracted/s83fd00/vault/inode_71.bin` | 8.9 MB |
| `work/extracted/s83fd00/vault/inode_72.bin` | 641.4 KB |
| `work/extracted/s83fd00/vault/inode_73.bin` | 10.9 MB |
| `work/extracted/s83fd00/vault/inode_75.bin` | 3.5 MB |
| `work/extracted/s83fd00/vault/inode_76.bin` | 759.9 KB |
| `work/extracted/s83fd00/vault/inode_77.bin` | 5.3 MB |
| `work/extracted/s83fd00/vault/inode_78.bin` | 1.2 MB |
| `work/extracted/s83fd00/vault/inode_79.bin` | 1.3 MB |
| `work/extracted/s83fd00/vault/inode_81.bin` | 6.0 MB |
| `work/extracted/s83fd00/vault/inode_82.bin` | 6.8 MB |
| `work/extracted/s83fd00/vault/inode_83.bin` | 9.2 MB |
| `work/extracted/s83fd00/vault/requirements.txt` | 57 B |
| `work/extracted/s83fd00/vault_ntfs.raw` | 1.9 GB |
| `work/extracted/s83fd01/776AR-04U.PDF.lnk` | 474 B |
| `work/extracted/s83fd01/B500 ATM Technical Documentation.pdf.lnk` | 567 B |
| `work/extracted/s83fd01/BitLocker Recovery Key.lnk` | 2.1 KB |
| `work/extracted/s83fd01/Capture.png` | 118.5 KB |
| `work/extracted/s83fd01/Capture2.png` | 397.8 KB |
| `work/extracted/s83fd01/Capture2.png.Zone.Identifier` | 92 B |
| `work/extracted/s83fd01/Capture2.trailer.bin` | 357.4 KB |
| `work/extracted/s83fd01/Spending.xlsx.lnk` | 474 B |
| `work/extracted/s83fd01/Vault (Y).lnk` | 349 B |
| `work/extracted/s83fd01/electron-config.json` | 26 B |
| `work/extracted/s83fd01/ready.lnk` | 1.9 KB |
| `work/extracted/s83fd01/sso-sessions.json` | 84 B |
| `work/extracted/s83fd02/776AR-04U.PDF.lnk` | 474 B |
| `work/extracted/s83fd02/B500_ATM.lnk` | 567 B |
| `work/extracted/s83fd02/BitLocker_Recovery.lnk` | 2.1 KB |
| `work/extracted/s83fd02/Capture.lnk` | 430 B |
| `work/extracted/s83fd02/Capture.png` | 118.5 KB |
| `work/extracted/s83fd02/Capture2.lnk` | 640 B |
| `work/extracted/s83fd02/Capture2.png` | 397.8 KB |
| `work/extracted/s83fd02/Capture2.png.Zone.Identifier` | 92 B |
| `work/extracted/s83fd02/Capture31231.lnk` | 2.0 KB |
| `work/extracted/s83fd02/Spending.xlsx.lnk` | 474 B |
| `work/extracted/s83fd02/Vault_Y.lnk` | 349 B |
| `work/extracted/s83fd02/electron-config.json` | 26 B |
| `work/extracted/s83fd02/element_events.db` | 80.0 KB |
| `work/extracted/s83fd02/element_events.db-shm` | 32.0 KB |
| `work/extracted/s83fd02/element_events.db-wal` | 0 B |
| `work/extracted/s83fd02/iphone/private/var/mobile/Containers/Shared/AppGroup/AF67BA79-B4B6-4F89-AD78-9054620F3322/NoteStore.sqlite` | 300.0 KB |
| `work/extracted/s83fd02/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0002.PNG` | 548.9 KB |
| `work/extracted/s83fd02/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0008.PNG` | 1.0 MB |
| `work/extracted/s83fd02/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0009.JPG` | 35.7 KB |
| `work/extracted/s83fd02/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0010.JPG` | 34.1 KB |
| `work/extracted/s83fd02/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0011.PNG` | 1.9 MB |
| `work/extracted/s83fd02/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0027.JPG` | 28.8 KB |
| `work/extracted/s83fd02/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0028.JPG` | 24.0 KB |
| `work/extracted/s83fd02/iphone/private/var/mobile/Media/DCIM/100APPLE/IMG_0032.PNG` | 85.5 KB |
| `work/extracted/s83fd02/iphone/private/var/mobile/Media/PhotoData/Photos.sqlite` | 2.2 MB |
| `work/extracted/s83fd02/iphone/private/var/mobile/Media/PhotoData/Photos.sqlite-shm` | 32.0 KB |
| `work/extracted/s83fd02/iphone/private/var/mobile/Media/PhotoData/Photos.sqlite-wal` | 0 B |
| `work/extracted/s83fd02/ready.lnk` | 1.9 KB |
| `work/extracted/s83fd02/vault/776AR-04U.PDF` | 378.9 KB |
| `work/extracted/s83fd02/vault/B500_ATM.pdf` | 9.2 MB |
| `work/extracted/s83fd02/vault/Detailed_specification_for_Laser_Printer-Color.pdf` | 55.3 KB |
| `work/extracted/s83fd02/vault/Spending.xlsx` | 7.0 KB |
| `work/extracted/s83fd02/vault/ZV-123_OnlineManual.pdf` | 3.7 MB |
| `work/extracted/s83fd02/vault/bot.py` | 7.2 KB |
| `work/extracted/s83fd03/Capture.png` | 118.5 KB |
| `work/extracted/s83fd03/Capture2.png` | 397.8 KB |
| `work/extracted/s83fd03/ICAIP8720.pdf` | 3.4 MB |
| `work/extracted/s83fd03/Module1.xba` | 1.1 KB |
| `work/extracted/s83fd03/NTUSER.DAT` | 1.3 MB |
| `work/extracted/s83fd03/SOFTWARE` | 72.5 MB |
| `work/extracted/s83fd03/Spending.xlsx` | 7.0 KB |
| `work/extracted/s83fd03/bot.py` | 7.2 KB |
| `work/extracted/s83fd03/el_cookies` | 20.0 KB |
| `work/extracted/s83fd03/els_000003.log` | 4.5 KB |
| `work/extracted/s83fd03/els_LOG` | 292 B |
| `work/extracted/s83fd03/events.db` | 80.0 KB |
| `work/extracted/s83fd03/places.sqlite` | 5.0 MB |
| `work/extracted/s83fd03/places.sqlite-shm` | 32.0 KB |
| `work/extracted/s83fd03/places.sqlite-wal` | 0 B |
| `work/extracted/s83fd03/registrymodifications.xcu` | 189.4 KB |
| `work/extracted/s83fd03/requirements.txt` | 57 B |
| `work/extracted/s83fd03/vault.vhdx` | 580.0 MB |
| `work/extracted/s83fd03/webappsstore.sqlite` | 96.0 KB |
| `work/extracted/s83fd06/edge_history.db` | 256.0 KB |
| `work/extracted/s83fd06/element_events.db` | 80.0 KB |
| `work/extracted/s83fd06/private/var/mobile/Containers/Shared/AppGroup/A667456A-6F8F-48C7-A8CF-37EFCC6BD644/telegram-data/account-112545592466388074/postbox/db/db_sqlite` | 7.2 MB |
| `work/extracted/s83fd06/private/var/mobile/Library/Accounts/Accounts3.sqlite` | 220.0 KB |
| `work/extracted/s83fd06/private/var/mobile/Library/Accounts/Accounts3.sqlite-shm` | 32.0 KB |
| `work/extracted/s83fd06/private/var/mobile/Library/Accounts/Accounts3.sqlite-wal` | 0 B |
| `work/extracted/s83fd06/private/var/mobile/Library/SMS/sms.db` | 288.0 KB |
| `work/extracted/s83fd06/private/var/mobile/Library/SMS/sms.db-shm` | 32.0 KB |
| `work/extracted/s83fd06/private/var/mobile/Library/SMS/sms.db-wal` | 0 B |
| `work/extracted/s83fd06/tg_strings_full.txt` | 799.8 KB |
| `work/extracted/s83fd07/101902.tmp` | 7.2 KB |
| `work/extracted/s83fd07/102541.tmp` | 24 B |
| `work/extracted/s83fd07/102543.tmp` | 1.0 MB |
| `work/extracted/s83fd07/B500_ATM_Technical_Documentation.pdf.lnk` | 567 B |
| `work/extracted/s83fd07/BitLocker-Management.evtx` | 68.0 KB |
| `work/extracted/s83fd07/BitLockerRecoveryKey.lnk` | 2.1 KB |
| `work/extracted/s83fd07/Documents_desktop.ini` | 490 B |
| `work/extracted/s83fd07/Edge-History.sqlite` | 256.0 KB |
| `work/extracted/s83fd07/Edge-LoginData.sqlite` | 56.0 KB |
| `work/extracted/s83fd07/Edge-WebData.sqlite` | 224.0 KB |
| `work/extracted/s83fd07/NTUSER.DAT` | 1.3 MB |
| `work/extracted/s83fd07/SAM` | 64.0 KB |
| `work/extracted/s83fd07/SECURITY` | 32.0 KB |
| … and 5 more | |
| `work/s83fd00/` (scratch of s83fd00) | 0 files, 0 B |
| `work/s83fd01/` (scratch of s83fd01) | 14 files, 2.1 MB |
| `work/s83fd02/` (scratch of s83fd02) | 26 files, 1.3 MB |
| `work/s83fd04/` (scratch of s83fd04) | 26 files, 9.3 MB |
| `work/s83fd05/` (scratch of s83fd05) | 18 files, 4.5 GB |
| `work/s83fd07/` (scratch of s83fd07) | 56 files, 1.9 GB |
| `work/s83fd08/` (scratch of s83fd08) | 1 files, 965.9 KB |

## Custody

Inputs from `/Users/halilozturkci/DFIR/SwarmInputs/belkactf6`, copied 2026-09-21T11:06:04Z: 8 files, 13.5 GB; enforcement asked auto, kickoff guard seatbelt.

| Input | Bytes | SHA-256 |
| --- | --- | --- |
| `inputs/BelkaCTF_6_CASE240405_D201AP.tar` | 5,134,817,280 | `4ef69a6292cdffd63fc4d0a5bc47ca98fa47ad59cc7846140e24cf1e30214aff` |
| `inputs/BelkaCTF_6_CASE240405_LAPTOP.E01` | 1,572,760,540 | `5528361e35f711f1f3056404dc1649f1c6d6ae099037b47217c73ee18d83e56e` |
| `inputs/BelkaCTF_6_CASE240405_LAPTOP.E02` | 1,572,789,996 | `05a9b653f35864c997362afb7f9d8152a57ea0f9ad3c18bed8e315a5d859a405` |
| `inputs/BelkaCTF_6_CASE240405_LAPTOP.E03` | 1,572,786,181 | `e6561b9f0e633b744d5454131613a5bf0c69f7d0bb6b61c15845419fc43f2a2f` |
| `inputs/BelkaCTF_6_CASE240405_LAPTOP.E04` | 1,572,784,241 | `384de0059098db8312f6f6b52b43f509569eaec99b77cf3b6703021461b08ed2` |
| `inputs/BelkaCTF_6_CASE240405_LAPTOP.E05` | 1,572,699,571 | `a7d826d58aa1548c37e7483a19e6b0f404d72564a010160947ecf764b6b5319a` |
| `inputs/BelkaCTF_6_CASE240405_LAPTOP.E06` | 1,470,470,243 | `8adb8259c2df9c984741b07ee35b888c3d43193a882039747a08a5e9de2406b6` |
| `inputs/CASE.md` | 1,561 | `e01f34a4d7be3dfe4c16084ed3ea195ee7b4f572c14232a742aa9a1b4d5dcef7` |

| Inputs check | By | Result |
| --- | --- | --- |
| 2026-09-21T12:06:39.497Z | s83fd07 | intact: 8 checked, 0 modified, 0 missing, 0 added |
| 2026-09-21T12:06:40.979Z | s83fd08 | intact: 8 checked, 0 modified, 0 missing, 0 added |
| 2026-09-21T12:07:04.310Z | s83fd04 | intact: 8 checked, 0 modified, 0 missing, 0 added |
| 2026-09-21T12:07:06.177Z | s83fd05 | intact: 8 checked, 0 modified, 0 missing, 0 added |

Toolbox (dfir): 12 present — mmls (The Sleuth Kit ver 4.15.0), fls (The Sleuth Kit ver 4.15.0), icat (The Sleuth Kit ver 4.15.0), mactime (The Sleuth Kit ver 4.15.0), vol (Volatility 3 Framework 2.28.2), regipy-dump (6.3.0), evtx_dump (python-evtx ok), yara (4.5.8), exiftool (12.92), sqlite3 (3.54.0 2026-04-09 12:25:13 8fa8248e303219400c646a885e36dfc52eae33d83f4412e3f369b2be5373aapl (64-bit)), strings (error: /Library/Developer/CommandLineTools/usr/bin/strings: unknown flag: --version), python3 (Python 3.12.1); 1 missing — esedbexport.

Evidence catalog: 1 disk image(s), 0 memory image(s), 5 catalog file(s).
