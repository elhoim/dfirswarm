# Run summary: s821c — belkactf6

- State: done · sentinel present
- Started: 2026-09-20T18:03:46Z · Duration: 50m 32s (to the sentinel at 2026-09-20T18:54:17.540Z)
- Case: BELKACTF6 · Examiner: Halil Ozturkci
- Kickoff: model 3xazure-foundry/grok-4.6 + 2xazure-foundry/DeepSeek-V4-Pro + 2xdeepseek/deepseek-v4-pro + 2xopenai/gpt-5.4 + 1xlmstudio/qwen3.8-27b-uncensored · catalog · toolbox dfir · quarantine · allow-host api.wigle.net,wigle.net,nominatim.openstreetmap.org
- Sandbox: `/Users/halilozturkci/DFIR/dfirswarm-runs/s821c`

## Outcome

Sentinel `done/SWARM_DONE` by **s821c04** at 2026-09-20T18:54:17.540Z: Posts #83-#103 are status updates, tool refinements, and hypotheses I already incorporated into my final summary (#102). Key posts: #103 is critic sign-off confirming structural deliverables. #101 lists low/medium hypotheses for open questions — these are in flags.md already. #88 confirms Vault protector GUID match. None change the core finding: BitLocker VHDX remains locked, 7 high-confidence answers, 11 questions with partial/low evidence or blocked. Swarm has met all structural done checks. (output: `work/report.md`)

| Agent | Marker | At | Reason |
| --- | --- | --- | --- |
| s821c00 | done | 2026-09-20T18:54:25.774Z | Critic signed off; report/flags/timeline/dependencies exist. iPhone identity slice complete (Q1–Q3, Q17 SWIFT, BitLocker key, SecuEncrypt cipher). Remaining vault-gated questions blocked on BitLocker CCM. |
| s821c01 | done | 2026-09-20T18:54:27.951Z | sentinel_present |
| s821c02 | done | 2026-09-20T18:54:27.674Z | Swarm finished: SWARM_DONE present. Vault BitLocker CCM still locked; Q5/Q8 and supporting laptop identity already in ledger/flags. |
| s821c03 | — |  |  |
| s821c04 | done | 2026-09-20T18:54:17.540Z | Posts #83-#103 are status updates, tool refinements, and hypotheses I already incorporated into my final summary (#102). Key posts: #103 is critic sign-off confirming structural deliverables. #101 lists low/medium hypotheses for open questions — these are in flags.md already. #88 confirms Vault protector GUID match. None change the core finding: BitLocker VHDX remains locked, 7 high-confidence answers, 11 questions with partial/low evidence or blocked. Swarm has met all structural done checks. |
| s821c05 | — |  |  |
| s821c06 | — |  |  |
| s821c07 | done | 2026-09-20T18:54:19.932Z | sentinel_present |
| s821c08 | done | 2026-09-20T18:54:21.975Z | swarm_done |
| s821c09 | — |  |  |

6 of 10 agents marked; without a marker: s821c03, s821c05, s821c06, s821c09.

## Team

| Agent | Calls itself | Role | Model | Spent | Calls | Tokens |
| --- | --- | --- | --- | --- | --- | --- |
| s821c00 | iPhone identity — Q1/Q2 done; parsing peer Telegram extracts for Q3 usernames and extracting iPhone location artefacts for Q4/Q7 | worker | azure-foundry/grok-4.6 | $12.35 | 128 | 10,768,890 |
| s821c01 | Docs and money — Hunt Q6 first take, Q9 luxury item, Q10 concert, Q11 template designer, Q16 leak source from catalogs and targeted extracts; seed work/flags.md as answers land. | worker | azure-foundry/grok-4.6 | $10.81 | 105 | 9,320,579 |
| s821c02 | Vault unlock — Unlock BitLocker vault.vhdx with the iPhone Notes recovery key, then extract Y: files (Spending.xlsx, 776AR-04U.PDF, B500 ATM PDF, baker) for Q6/Q9/Q15–Q18. | worker | azure-foundry/grok-4.6 | $9.44 | 69 | 7,609,009 |
| s821c03 | Location & Venue Hunter — Q4 William's location, Q7 March celebration venue, Q10 concert from iPhone location data, Wi-Fi networks, photos EXIF, and Telegram chat context | worker | azure-foundry/DeepSeek-V4-Pro | $14.33 | 237 | 15,333,582 |
| s821c04 | Laptop Deep Dive — Laptop evidence analysis: chasing Drew's full name, Q7 bar venue, Q10 concert details, Q14 printer model — plus trying BitLocker key variations on VHDX | worker | azure-foundry/DeepSeek-V4-Pro | $13.40 | 217 | 16,109,140 |
| s821c05 | iPhone Identity & Telegram — Answer Q1 (Apple ID), Q2 (owner full name), Q3 (Telegram accounts) from the iPhone image, and chase William/home leads for Q4. | worker | deepseek/deepseek-v4-pro | $0.11 | 28 | 646,369 |
| s821c06 | laptop-analyst — Analysing the Windows laptop image (EWF) for the laptop-side answers: username, encrypted container, printer, lab, ATM, bank/SWIFT, bank statement, concert, luxury item, template designer, timestamps. | worker | deepseek/deepseek-v4-pro | $0.12 | 24 | 558,007 |
| s821c07 | Dependency & Timeline — Owning cross-question dependency mapping and merged timeline assembly from the ledger, plus citation verification for findings peers post; will avoid primary laptop-recon overlap unless a gap appears | worker | openai/gpt-5.4 | $11.17 | 272 | 34,460,865 |
| s821c08 | Laptop Recon — Taking initial laptop-side triage: identify Windows user, look for encrypted container, printer, ATM/banking and timeline artifacts, then feed dependencies/flags with evidence-backed findings. | worker | openai/gpt-5.4 | $5.60 | 107 | 16,360,236 |
| s821c09 |  | worker | lmstudio/qwen3.8-27b-uncensored | $0.00 | 9 | 134,449 |

By model:

| Model | Spent | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| azure-foundry/grok-4.6 | $32.60 | 42% | 302 | 3 (s821c00, s821c01, s821c02) |
| azure-foundry/DeepSeek-V4-Pro | $27.73 | 36% | 454 | 2 (s821c03, s821c04) |
| openai/gpt-5.4 | $16.77 | 22% | 379 | 2 (s821c07, s821c08) |
| deepseek/deepseek-v4-pro | $0.23 | 0% | 52 | 2 (s821c05, s821c06) |
| lmstudio/qwen3.8-27b-uncensored | $0.00 | 0% | 9 | 1 (s821c09) |

Spent $77.32 of a $100.00 cap, $15.00 per agent; 1196 provider calls, 111,301,126 tokens.

## Activity

2287 trace events from 2026-09-20T18:03:56.595Z to 2026-09-20T18:54:28.051Z.

| Agent | Events | Top tools |
| --- | --- | --- |
| s821c07 | 428 | thinking 86, inbox 47, wait 44, file_history 37, claim_file 35 |
| s821c03 | 368 | bash 165, thinking 120, claim_file 33, inbox 11, tool_loaded 8 |
| s821c04 | 357 | bash 143, thinking 108, claim_file 32, inbox 14, read 9 |
| s821c00 | 279 | claim_file 68, bash 64, read 23, wait 23, record 17 |
| s821c01 | 238 | bash 67, claim_file 58, read 28, sqlite_query 15, record 10 |
| s821c08 | 229 | bash 74, wait 53, thinking 34, claim_file 20, read 8 |
| s821c02 | 176 | bash 79, claim_file 34, read 19, tool_loaded 8, inbox 6 |
| s821c06 | 85 | bash 19, thinking 16, claim_file 14, file_history 14, read 6 |
| s821c05 | 65 | bash 21, thinking 20, tool_loaded 6, read 4, claim_file 3 |
| system | 38 | idle_nudge 38 |
| s821c09 | 24 | tool_loaded 6, read 5, thinking 5, bash 3, agent_start 1 |

| Signal | Count |
| --- | --- |
| claim violations | 2 |
| implicit claims (shell writes turned into claims) | 259 |
| inputs violations | 0 |
| inputs checks | 4 |
| forge hints | 5 |
| sentinel nudges | 1 |
| idle nudges | 38 |
| per-agent cap steers | 0 |
| per-agent cap stops | 0 |
| posts | 62 |
| bash calls | 655 |

Forged tools:

- `sqlite_query` by s821c01 at 2026-09-20T18:17:58.864Z (python3; called 38 times)
- `gzip_note` by s821c01 at 2026-09-20T18:17:58.886Z (python3; called 5 times)
- `blob_strings` by s821c00 at 2026-09-20T18:22:24.381Z (python3; called 9 times)
- `affine_decrypt` by s821c01 at 2026-09-20T18:33:57.620Z (python3; called 0 times)
- `bde_unlock` by s821c02 at 2026-09-20T18:34:07.538Z (python3; called 12 times)
- `bde_unlock2` by s821c00 at 2026-09-20T18:44:48.111Z (python3; called 15 times)
- `bde_unlock2` by s821c00 at 2026-09-20T18:47:40.638Z (python3; called 15 times)
- `bde_unlock2` by s821c00 at 2026-09-20T18:49:06.604Z (python3; called 15 times)

Bash leading commands (top 10):

| Command | Runs |
| --- | --- |
| `python3` | 116 |
| `grep` | 75 |
| `tar` | 39 |
| `sqlite3` | 27 |
| `echo` | 23 |
| `mkdir` | 19 |
| `ls` | 18 |
| `strings` | 18 |
| `icat` | 9 |
| `find` | 8 |

## Ledger

57 entries: 21 events, 11 indicators, 25 findings (`ledger/ledger.md`).

Last 10 events in time order:

| Time (UTC) | Event | Source | By |
| --- | --- | --- | --- |
| 2024-02-02T22:26:53.000Z | The Desktop file Powder.exe is timestamped in the phorger profile. | catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/bodyfile.txt | s821c07 |
| 2024-03-02T00:00:00.000Z | iPhone screenshot of Google Authenticator for Crooked River Bank (crbk.org) | private/var/mobile/Media/DCIM/100APPLE/IMG_0032.PNG | s821c00 |
| 2024-03-18T18:53:20.000Z | The iTunes device file iPodDevices.xml is timestamped under the phorger profile. | catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/bodyfile.txt | s821c07 |
| 2024-03-20T10:31:10.000Z | iPhone Safari visited Crooked River Bank (crbk.org) including forgot-password | private/var/mobile/Library/Safari/History.db | s821c00 |
| 2024-03-26T00:00:00.000Z | Bank UI screenshot Capture2.png shows PAB debit AIRBNB 14158B00005959 -47.3 PAB | Users/phorger/Pictures/Capture2.png inode 113422-128-3 | s821c01 |
| 2024-03-27T00:00:00.000Z | Bank UI screenshot Capture2.png shows PAB debit LAARI ADA St. Louis -33.25 PAB | Users/phorger/Pictures/Capture2.png inode 113422-128-3 | s821c01 |
| 2024-04-01T00:00:00.000Z | Gang reports ATM rejecting cash; stubborn machine linked at https://bit.ly/3VKt3er | Telegram the.party chat t7 | s821c02 |
| 2024-04-01T09:59:49.000Z | Firefox web.telegram.org cache files are timestamped under the phorger profile. | catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/bodyfile.txt | s821c07 |
| 2024-04-05T00:29:01.000Z | ConnectedDevicesPlatform ActivitiesCache.db is timestamped under the phorger profile. | catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/bodyfile.txt | s821c07 |
| 2024-04-05T00:29:02.000Z | Comms UnistoreDB store.vol is timestamped under the phorger profile. | catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/bodyfile.txt | s821c07 |

## Work

| File | Size |
| --- | --- |
| `work/dependencies.md` | 6.6 KB |
| `work/flags.md` | 3.8 KB |
| `work/report.md` | 7.8 KB |
| `work/timeline.md` | 6.4 KB |
| `work/extracted/s821c00/private/var/containers/Data/System/23801560-4E89-4EBB-B41C-A73FF3AF4FE8/Library/activation_records/activation_record.plist` | 7.7 KB |
| `work/extracted/s821c00/private/var/containers/Data/System/23801560-4E89-4EBB-B41C-A73FF3AF4FE8/Library/internal/data_ark.plist` | 8.1 KB |
| `work/extracted/s821c00/private/var/mobile/Containers/Shared/AppGroup/AF67BA79-B4B6-4F89-AD78-9054620F3322/NoteStore.sqlite` | 292.0 KB |
| `work/extracted/s821c00/private/var/mobile/Containers/Shared/AppGroup/AF67BA79-B4B6-4F89-AD78-9054620F3322/NoteStore.sqlite-shm` | 32.0 KB |
| `work/extracted/s821c00/private/var/mobile/Containers/Shared/AppGroup/AF67BA79-B4B6-4F89-AD78-9054620F3322/NoteStore.sqlite-wal` | 325.9 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Accounts/Accounts3.sqlite` | 220.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Accounts/Accounts3.sqlite-shm` | 32.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Accounts/Accounts3.sqlite-wal` | 0 B |
| `work/extracted/s821c00/private/var/mobile/Library/Accounts/persona.cache` | 413 B |
| `work/extracted/s821c00/private/var/mobile/Library/AddressBook/AddressBook.sqlitedb` | 300.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/AddressBook/AddressBook.sqlitedb-shm` | 32.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/AddressBook/AddressBook.sqlitedb-wal` | 0 B |
| `work/extracted/s821c00/private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite` | 4.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite-shm` | 32.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Caches/com.apple.routined/Cache.sqlite-wal` | 877.1 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Caches/com.apple.routined/Cloud-V2.sqlite` | 4.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Caches/com.apple.routined/Cloud-V2.sqlite-shm` | 32.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Caches/com.apple.routined/Cloud-V2.sqlite-wal` | 591.5 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Caches/com.apple.routined/Local.sqlite` | 4.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Caches/com.apple.routined/Local.sqlite-shm` | 32.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Caches/com.apple.routined/Local.sqlite-wal` | 474.8 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Calendar/Calendar.sqlitedb` | 944.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Calendar/Calendar.sqlitedb-shm` | 32.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Calendar/Calendar.sqlitedb-wal` | 16.1 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Maps/navd.cache` | 4.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Maps/navd.cache-wal` | 76.5 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Notes/notes.sqlite` | 140.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Notes/notes.sqlite-wal` | 128.8 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Reminders/Container_v1/Stores/Data-local.sqlite` | 580.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Reminders/Container_v1/Stores/Data-local.sqlite-shm` | 32.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Reminders/Container_v1/Stores/Data-local.sqlite-wal` | 12.1 KB |
| `work/extracted/s821c00/private/var/mobile/Library/SMS/sms.db` | 288.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/SMS/sms.db-shm` | 32.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/SMS/sms.db-wal` | 587.5 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Safari/Bookmarks.db` | 4.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Safari/Bookmarks.db-shm` | 32.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Safari/Bookmarks.db-wal` | 1.8 MB |
| `work/extracted/s821c00/private/var/mobile/Library/Safari/BrowserState.db` | 1.7 MB |
| `work/extracted/s821c00/private/var/mobile/Library/Safari/BrowserState.db-wal` | 2.7 MB |
| `work/extracted/s821c00/private/var/mobile/Library/Safari/History.db` | 136.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Safari/History.db-shm` | 32.0 KB |
| `work/extracted/s821c00/private/var/mobile/Library/Safari/History.db-wal` | 0 B |
| `work/extracted/s821c00/private/var/mobile/Library/Shortcuts/Shortcuts.sqlite` | 328.0 KB |
| `work/extracted/s821c00/private/var/mobile/Media/DCIM/100APPLE/IMG_0002.PNG` | 548.9 KB |
| `work/extracted/s821c00/private/var/mobile/Media/DCIM/100APPLE/IMG_0008.PNG` | 1.0 MB |
| `work/extracted/s821c00/private/var/mobile/Media/DCIM/100APPLE/IMG_0009.JPG` | 35.7 KB |
| `work/extracted/s821c00/private/var/mobile/Media/DCIM/100APPLE/IMG_0010.JPG` | 34.1 KB |
| `work/extracted/s821c00/private/var/mobile/Media/DCIM/100APPLE/IMG_0011.PNG` | 1.9 MB |
| `work/extracted/s821c00/private/var/mobile/Media/DCIM/100APPLE/IMG_0027.JPG` | 28.8 KB |
| `work/extracted/s821c00/private/var/mobile/Media/DCIM/100APPLE/IMG_0028.JPG` | 24.0 KB |
| `work/extracted/s821c00/private/var/mobile/Media/DCIM/100APPLE/IMG_0029.WEBP` | 71.4 KB |
| `work/extracted/s821c00/private/var/mobile/Media/DCIM/100APPLE/IMG_0030.WEBP` | 71.4 KB |
| `work/extracted/s821c00/private/var/mobile/Media/DCIM/100APPLE/IMG_0032.PNG` | 85.5 KB |
| `work/extracted/s821c00/private/var/mobile/Media/PhotoData/Photos.sqlite` | 2.2 MB |
| `work/extracted/s821c00/private/var/mobile/Media/PhotoData/Photos.sqlite-shm` | 32.0 KB |
| `work/extracted/s821c00/private/var/mobile/Media/PhotoData/Photos.sqlite-wal` | 3.4 MB |
| `work/extracted/s821c00/private/var/preferences/SystemConfiguration/com.apple.wifi-networks.plist` | 42 B |
| `work/extracted/s821c00/private/var/preferences/com.apple.wifi.known-networks.plist` | 1.3 KB |
| `work/extracted/s821c00/private/var/root/Library/Caches/locationd/consolidated.db` | 64.0 KB |
| `work/extracted/s821c00/private/var/root/Library/Caches/locationd/consolidated.db-shm` | 32.0 KB |
| `work/extracted/s821c00/private/var/root/Library/Caches/locationd/consolidated.db-wal` | 32.2 KB |
| `work/extracted/s821c00/private/var/root/Library/Preferences/com.apple.wifi.manager.plist` | 2.9 KB |
| `work/extracted/s821c00/sms/private/var/mobile/Containers/Data/Application/C77DAB23-6182-42FB-A253-9F4CC57338EF/Library/Preferences/com.spotify.client.plist` | 117 B |
| `work/extracted/s821c00/sms/private/var/mobile/Library/SMS/sms.db` | 288.0 KB |
| `work/extracted/s821c00/sms/private/var/mobile/Library/SMS/sms.db-shm` | 32.0 KB |
| `work/extracted/s821c00/sms/private/var/mobile/Library/SMS/sms.db-wal` | 587.5 KB |
| `work/extracted/s821c01/776AR-04U.PDF.lnk` | 474 B |
| `work/extracted/s821c01/B500_ATM.PDF.lnk` | 567 B |
| `work/extracted/s821c01/BitLockerRecovery.lnk` | 2.1 KB |
| `work/extracted/s821c01/Capture.png` | 118.5 KB |
| `work/extracted/s821c01/Capture2.png` | 397.8 KB |
| `work/extracted/s821c01/Capture31231.lnk` | 2.0 KB |
| `work/extracted/s821c01/Spending.xlsx.lnk` | 474 B |
| `work/extracted/s821c01/Vault_Y.lnk` | 349 B |
| `work/extracted/s821c01/browser/edge_History` | 256.0 KB |
| `work/extracted/s821c01/browser/places.sqlite` | 5.0 MB |
| `work/extracted/s821c01/element/blobs/2` | 463.1 KB |
| `work/extracted/s821c01/element/blobs/3` | 554.4 KB |
| `work/extracted/s821c01/element/blobs/4` | 628.0 KB |
| `work/extracted/s821c01/element/blobs/5` | 385.1 KB |
| `work/extracted/s821c01/element/blobs/6` | 576.8 KB |
| `work/extracted/s821c01/element/blobs/7` | 612.8 KB |
| `work/extracted/s821c01/element/blobs/8` | 505.3 KB |
| `work/extracted/s821c01/element/blobs/9` | 485.2 KB |
| `work/extracted/s821c01/element/blobs/a` | 532.4 KB |
| `work/extracted/s821c01/element/blobs/b` | 506.8 KB |
| `work/extracted/s821c01/element/blobs/c` | 637.2 KB |
| `work/extracted/s821c01/element/blobs/d` | 225.0 KB |
| `work/extracted/s821c01/element/electron-config.json` | 26 B |
| `work/extracted/s821c01/element/events.db` | 80.0 KB |
| `work/extracted/s821c01/element/events.db-wal` | 330.0 KB |
| `work/extracted/s821c01/element/idb_000098.ldb` | 60.3 KB |
| `work/extracted/s821c01/element/idb_000099.log` | 980.1 KB |
| `work/extracted/s821c01/element/idb_000100.ldb` | 1.8 MB |
| `work/extracted/s821c01/element/localstorage_000003.log` | 4.5 KB |
| `work/extracted/s821c01/itunes/Info.plist` | 113.7 KB |
| `work/extracted/s821c01/itunes/Manifest.db` | 3.9 MB |
| `work/extracted/s821c01/itunes/Manifest.db-shm` | 32.0 KB |
| `work/extracted/s821c01/itunes/Manifest.db-wal` | 0 B |
| `work/extracted/s821c01/itunes/Manifest.plist` | 112.8 KB |
| `work/extracted/s821c01/itunes/files/NoteStore.sqlite` | 292.0 KB |
| `work/extracted/s821c01/itunes/files/NoteStore.sqlite-shm` | 32.0 KB |
| `work/extracted/s821c01/itunes/files/NoteStore.sqlite-wal` | 0 B |
| `work/extracted/s821c01/itunes/files/Photos.sqlite` | 1.9 MB |
| `work/extracted/s821c01/itunes/files/Photos.sqlite-shm` | 32.0 KB |
| `work/extracted/s821c01/itunes/files/Photos.sqlite-wal` | 0 B |
| `work/extracted/s821c01/itunes/files/keychain-backup.plist` | 395.8 KB |
| `work/extracted/s821c01/itunes/files/notes.sqlite` | 140.0 KB |
| `work/extracted/s821c01/itunes/files/notes.sqlite-shm` | 32.0 KB |
| `work/extracted/s821c01/itunes/files/notes.sqlite-wal` | 0 B |
| `work/extracted/s821c01/itunes/files/telegram.plist` | 192 B |
| `work/extracted/s821c01/ituneslib/private/var/mobile/Media/iTunes_Control/iTunes/MediaLibrary.sqlitedb` | 4.0 KB |
| `work/extracted/s821c01/ready.lnk` | 1.9 KB |
| `work/extracted/s821c01/registrymodifications.xcu` | 189.4 KB |
| `work/extracted/s821c01/sms/private/var/mobile/Library/SMS/sms.db` | 288.0 KB |
| `work/extracted/s821c01/sms/private/var/mobile/Library/SMS/sms.db-shm` | 32.0 KB |
| `work/extracted/s821c01/sms/private/var/mobile/Library/SMS/sms.db-wal` | 587.5 KB |
| `work/extracted/s821c01/splitwise/private/var/mobile/Containers/Data/Application/E951DC58-CF30-4518-9482-3E076D89A20B/Library/Caches/com.Splitwise.SplitwiseMobile/Cache.db` | 48.0 KB |
| `work/extracted/s821c01/splitwise/private/var/mobile/Containers/Data/Application/E951DC58-CF30-4518-9482-3E076D89A20B/Library/Caches/com.Splitwise.SplitwiseMobile/Cache.db-shm` | 32.0 KB |
| `work/extracted/s821c01/splitwise/private/var/mobile/Containers/Data/Application/E951DC58-CF30-4518-9482-3E076D89A20B/Library/Caches/com.Splitwise.SplitwiseMobile/Cache.db-wal` | 0 B |
| `work/extracted/s821c01/splitwise/private/var/mobile/Containers/Data/Application/E951DC58-CF30-4518-9482-3E076D89A20B/Library/Caches/com.Splitwise.SplitwiseMobile/fsCachedData/451CBB40-753F-4FBB-A569-F0B6DDAC56BF` | 6.0 KB |
| `work/extracted/s821c01/splitwise/private/var/mobile/Containers/Data/Application/E951DC58-CF30-4518-9482-3E076D89A20B/Library/Caches/com.Splitwise.SplitwiseMobile/fsCachedData/CA396F86-E7A8-4209-9F19-637CB2BCAD08` | 5.3 KB |
| `work/extracted/s821c01/splitwise/private/var/mobile/Containers/Data/Application/E951DC58-CF30-4518-9482-3E076D89A20B/Library/HTTPStorages/com.Splitwise.SplitwiseMobile/httpstorages.sqlite` | 4.0 KB |
| `work/extracted/s821c01/splitwise/private/var/mobile/Containers/Data/Application/E951DC58-CF30-4518-9482-3E076D89A20B/Library/Preferences/com.Splitwise.SplitwiseMobile.plist` | 8.3 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0003.HEIC/5003.JPG` | 17.6 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0004.HEIC/5003.JPG` | 21.7 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0005.HEIC/5003.JPG` | 17.9 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0006.HEIC/5003.JPG` | 24.3 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0007.HEIC/5003.JPG` | 22.4 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0012.HEIC/5003.JPG` | 41.5 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0013.HEIC/5003.JPG` | 44.3 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0014.HEIC/5003.JPG` | 41.7 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0015.HEIC/5003.JPG` | 43.7 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0016.HEIC/5003.JPG` | 44.1 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0017.HEIC/5003.JPG` | 44.4 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0018.HEIC/5003.JPG` | 44.6 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0019.HEIC/5003.JPG` | 44.4 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0020.HEIC/5003.JPG` | 43.2 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0021.HEIC/5003.JPG` | 40.7 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0022.HEIC/5003.JPG` | 43.2 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0023.HEIC/5003.JPG` | 44.0 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0024.HEIC/5003.JPG` | 42.5 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0025.HEIC/5003.JPG` | 40.3 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0026.HEIC/5003.JPG` | 28.1 KB |
| `work/extracted/s821c01/thumbs/private/var/mobile/Media/PhotoData/Thumbnails/V2/DCIM/100APPLE/IMG_0036.HEIC/5003.JPG` | 10.1 KB |
| `work/extracted/s821c01/tiktok/private/var/mobile/Containers/Data/Application/25D6FC89-3F45-4C53-8502-110948744484/Library/AWEStorage/UnifyStorage.sqlite` | 9.4 MB |
| `work/extracted/s821c01/tiktok/private/var/mobile/Containers/Data/Application/25D6FC89-3F45-4C53-8502-110948744484/Library/Preferences/com.zhiliaoapp.musically.plist` | 163.4 KB |
| `work/extracted/s821c01/vault/vault_head.bin` | 80.0 KB |
| `work/extracted/s821c02/el/electron-config.json` | 26 B |
| `work/extracted/s821c02/el/events.db` | 80.0 KB |
| `work/extracted/s821c02/el/idb/103085.bin` | 485.2 KB |
| `work/extracted/s821c02/el/idb/103153.bin` | 554.4 KB |
| `work/extracted/s821c02/el/idb/103154.bin` | 576.8 KB |
| `work/extracted/s821c02/el/idb/103155.bin` | 628.0 KB |
| `work/extracted/s821c02/el/idb/103186.bin` | 463.1 KB |
| `work/extracted/s821c02/el/idb/103195.bin` | 612.8 KB |
| `work/extracted/s821c02/el/idb/103196.bin` | 532.4 KB |
| `work/extracted/s821c02/el/idb/103197.bin` | 385.1 KB |
| `work/extracted/s821c02/el/idb/103220.bin` | 506.8 KB |
| `work/extracted/s821c02/el/idb/103221.bin` | 637.2 KB |
| `work/extracted/s821c02/el/idb/103226.bin` | 225.0 KB |
| `work/extracted/s821c02/el/idb/34898.bin` | 505.3 KB |
| `work/extracted/s821c02/el/meta.json` | 1.8 KB |
| `work/extracted/s821c02/ff/cookies.sqlite` | 512.0 KB |
| `work/extracted/s821c02/ff/formhistory.sqlite` | 256.0 KB |
| `work/extracted/s821c02/ff/places.sqlite` | 5.0 MB |
| `work/extracted/s821c02/lnks/776AR-04U.PDF.lnk` | 474 B |
| `work/extracted/s821c02/lnks/B500_ATM.lnk` | 567 B |
| `work/extracted/s821c02/lnks/BitLocker_Recovery.lnk` | 2.1 KB |
| `work/extracted/s821c02/lnks/Spending.xlsx.lnk` | 474 B |
| `work/extracted/s821c02/lnks/Vault_Y.lnk` | 349 B |
| `work/extracted/s821c02/lnks/ready.lnk` | 1.9 KB |
| `work/extracted/s821c02/lo/Module1.xba` | 1.1 KB |
| `work/extracted/s821c02/photos/private/var/mobile/Media/DCIM/100APPLE/IMG_0002.PNG` | 548.9 KB |
| `work/extracted/s821c02/photos/private/var/mobile/Media/DCIM/100APPLE/IMG_0008.PNG` | 1.0 MB |
| `work/extracted/s821c02/photos/private/var/mobile/Media/DCIM/100APPLE/IMG_0009.JPG` | 35.7 KB |
| `work/extracted/s821c02/photos/private/var/mobile/Media/DCIM/100APPLE/IMG_0010.JPG` | 34.1 KB |
| `work/extracted/s821c02/photos/private/var/mobile/Media/DCIM/100APPLE/IMG_0011.PNG` | 1.9 MB |
| `work/extracted/s821c02/photos/private/var/mobile/Media/DCIM/100APPLE/IMG_0027.JPG` | 28.8 KB |
| `work/extracted/s821c02/photos/private/var/mobile/Media/DCIM/100APPLE/IMG_0028.JPG` | 24.0 KB |
| `work/extracted/s821c02/photos/private/var/mobile/Media/DCIM/100APPLE/IMG_0029.WEBP` | 71.4 KB |
| `work/extracted/s821c02/photos/private/var/mobile/Media/DCIM/100APPLE/IMG_0030.WEBP` | 71.4 KB |
| `work/extracted/s821c02/photos/private/var/mobile/Media/DCIM/100APPLE/IMG_0032.PNG` | 85.5 KB |
| `work/extracted/s821c02/pic/Capture.png` | 118.5 KB |
| `work/extracted/s821c02/pic/Capture2.png` | 397.8 KB |
| `work/extracted/s821c02/powder/powder.pref` | 437 B |
| `work/extracted/s821c02/reg/NTUSER.DAT` | 1.3 MB |
| `work/extracted/s821c03/iphone/accounts/private/var/mobile/Library/Accounts/Accounts3.sqlite` | 220.0 KB |
| `work/extracted/s821c03/iphone/accounts/private/var/mobile/Library/Accounts/Accounts3.sqlite-shm` | 32.0 KB |
| `work/extracted/s821c03/iphone/accounts/private/var/mobile/Library/Accounts/Accounts3.sqlite-wal` | 0 B |
| `work/extracted/s821c03/iphone/addressbook/private/var/mobile/Library/AddressBook/AddressBook.sqlitedb` | 4.0 KB |
| `work/extracted/s821c03/iphone/addressbook/private/var/mobile/Library/AddressBook/AddressBook.sqlitedb-shm` | 32.0 KB |
| `work/extracted/s821c03/iphone/addressbook/private/var/mobile/Library/AddressBook/AddressBook.sqlitedb-wal` | 0 B |
| `work/extracted/s821c03/iphone/private/var/mobile/Containers/Shared/AppGroup/A667456A-6F8F-48C7-A8CF-37EFCC6BD644/telegram-data/accounts-metadata/atomic-state` | 2.4 KB |
| `work/extracted/s821c03/iphone/private/var/mobile/Containers/Shared/AppGroup/A667456A-6F8F-48C7-A8CF-37EFCC6BD644/telegram-data/accounts-metadata/db/db_sqlite` | 4.0 KB |
| `work/extracted/s821c03/iphone/private/var/mobile/Containers/Shared/AppGroup/A667456A-6F8F-48C7-A8CF-37EFCC6BD644/telegram-data/accounts-metadata/spotlight/p:36891850763/avatar.png` | 34.5 KB |
| … and 4 more | |
| `work/s821c00/` (scratch of s821c00) | 3 files, 8.1 KB |
| `work/s821c01/` (scratch of s821c01) | 5 files, 5.4 MB |
| `work/s821c02/` (scratch of s821c02) | 1 files, 28.5 KB |
| `work/s821c05/` (scratch of s821c05) | 3 files, 18.1 MB |
| `work/s821c08/` (scratch of s821c08) | 18 files, 11.8 MB |

## Custody

Inputs from `/Users/halilozturkci/DFIR/SwarmInputs/belkactf6`, copied 2026-09-20T18:01:53Z: 8 files, 13.5 GB; enforcement asked on, kickoff guard seatbelt.

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
| 2026-09-20T18:54:17.539Z | s821c04 | intact: 8 checked, 0 modified, 0 missing, 0 added |
| 2026-09-20T18:54:21.975Z | s821c08 | intact: 8 checked, 0 modified, 0 missing, 0 added |
| 2026-09-20T18:54:25.773Z | s821c00 | intact: 8 checked, 0 modified, 0 missing, 0 added |
| 2026-09-20T18:54:27.673Z | s821c02 | intact: 8 checked, 0 modified, 0 missing, 0 added |

Toolbox (dfir): 12 present — mmls (The Sleuth Kit ver 4.15.0), fls (The Sleuth Kit ver 4.15.0), icat (The Sleuth Kit ver 4.15.0), mactime (The Sleuth Kit ver 4.15.0), vol (Volatility 3 Framework 2.28.2), regipy-dump (6.3.0), evtx_dump (python-evtx ok), yara (4.5.8), exiftool (12.92), sqlite3 (3.54.0 2026-04-09 12:25:13 8fa8248e303219400c646a885e36dfc52eae33d83f4412e3f369b2be5373aapl (64-bit)), strings (error: /Library/Developer/CommandLineTools/usr/bin/strings: unknown flag: --version), python3 (Python 3.12.1); 1 missing — esedbexport.

Evidence catalog: 6 disk image(s), 0 memory image(s), 30 catalog file(s).
