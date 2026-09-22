# Run summary: s864a — Challenge 9: Encrypt Them All (Azure, 9 seats)

- State: stopped · sentinel absent
- Started: 2026-09-18T16:04:48Z · Duration: 1h 32m (to the last trace event at 2026-09-18T17:37:41.667Z)
- Case: AH-C09 · Examiner: Halil Ozturkci
- Kickoff: model 4xazure-foundry/grok-4.6 + 5xazure-foundry/DeepSeek-V4-Pro · catalog · toolbox dfir · quarantine · allow-host isf-server.techanarchy.net
- Sandbox: `/Users/halilozturkci/DFIR/SampleCases/AliHadi-swarm/s864a`

## Outcome

No sentinel: the swarm has not finished (or was stopped from outside without one).

| Agent | Marker | At | Reason |
| --- | --- | --- | --- |
| s864a00 | — |  |  |
| s864a01 | — |  |  |
| s864a02 | — |  |  |
| s864a03 | — |  |  |
| s864a04 | — |  |  |
| s864a05 | — |  |  |
| s864a06 | — |  |  |
| s864a07 | — |  |  |
| s864a08 | — |  |  |

0 of 9 agents marked; without a marker: s864a00, s864a01, s864a02, s864a03, s864a04, s864a05, s864a06, s864a07, s864a08.

## Team

| Agent | Role | Model | Seat | Spent | Calls | Tokens |
| --- | --- | --- | --- | --- | --- | --- |
| s864a00 | worker | azure-foundry/grok-4.6 | Disk and file system: partitions and volumes (including the R2D2 volume and any BitLocker metadata `mmls`/`fsstat` reveal), $MFT, the file list, deleted entries; owns `work/disk.md`. | $14.08 | 64 | 7,444,931 |
| s864a01 | worker | azure-foundry/grok-4.6 | Recovery from file system journals: $LogFile, $UsnJrnl, volume shadow copies and unallocated space, for earlier copies of anything encrypted later; owns `work/recovery.md`. | $14.59 | 61 | 7,515,049 |
| s864a02 | worker | azure-foundry/grok-4.6 | Browser and application caches: browsers, mail, messaging and cloud clients, their caches, histories and databases, for the communication behind part 1; owns `work/caches.md`. | $14.87 | 62 | 7,860,377 |
| s864a03 | worker | azure-foundry/grok-4.6 | Registry and execution: SYSTEM/SOFTWARE/SAM/NTUSER, prefetch, shimcache, amcache, jump lists, LNK, scheduled tasks and services, to say what was run and when; owns `work/artifacts.md`. | $11.99 | 55 | 6,329,318 |
| s864a04 | worker | azure-foundry/DeepSeek-V4-Pro | Shell and user activity: PowerShell and cmd history, console host history, RunMRU, typed paths, recent documents, the Downloads and Documents folders as the user left them; owns `work/user-activity.md`. | $8.95 | 87 | 6,187,724 |
| s864a05 | worker | azure-foundry/DeepSeek-V4-Pro | BitLocker and volume encryption (part 2): the R2D2 volume, its recovery key or password wherever it was kept (registry, a printed key file, the user's own notes, Active Directory artefacts), the decryption itself, and what is inside; says exactly what this host cannot do; owns `work/bitlocker.md`. | $2.42 | 50 | 2,768,914 |
| s864a06 | worker | azure-foundry/DeepSeek-V4-Pro | Key material and cryptography (parts 1 and 3): the key pair and the keys file in Downloads, AES and OpenSSL/GPG artefacts, the decryption of the README and of the message, with the commands that prove each; owns `work/crypto.md`. | $16.26 | 125 | 14,032,786 |
| s864a07 | worker | azure-foundry/DeepSeek-V4-Pro | Timeline and ledger: records every dated event peers report with `record kind=event` and writes `work/timeline.md` from `ledger/ledger.md`. | $14.83 | 109 | 10,956,305 |
| s864a08 | worker | azure-foundry/DeepSeek-V4-Pro | Critic and editor: verifies every citation, challenges weak claims on the board, assembles `work/report.md` and posts the sign-off. | $10.49 | 133 | 10,003,673 |

By model:

| Model | Spent | Share | Calls | Agents |
| --- | --- | --- | --- | --- |
| azure-foundry/grok-4.6 | $55.53 | 51% | 242 | 4 (s864a00, s864a01, s864a02, s864a03) |
| azure-foundry/DeepSeek-V4-Pro | $52.95 | 49% | 504 | 5 (s864a04, s864a05, s864a06, s864a07, s864a08) |

Spent $108.48 of a $110.00 cap, $15.00 per agent; 746 provider calls, 73,099,077 tokens.

## Activity

1966 trace events from 2026-09-18T16:04:53.960Z to 2026-09-18T17:37:41.667Z.

| Agent | Events | Top tools |
| --- | --- | --- |
| s864a06 | 337 | bash 130, thinking 109, claim_file 79, inbox 5, read 5 |
| s864a08 | 292 | thinking 104, bash 94, claim_file 23, record 22, read 11 |
| s864a03 | 261 | claim_file 140, bash 41, wait 23, record 12, read 9 |
| s864a07 | 258 | thinking 92, record 54, wait 40, bash 19, inbox 9 |
| s864a04 | 193 | bash 63, thinking 59, record 16, read 8, wait 8 |
| s864a02 | 178 | bash 45, claim_file 40, read 22, record 12, wait 11 |
| s864a01 | 149 | bash 50, claim_file 20, wait 14, read 11, record 9 |
| s864a05 | 149 | thinking 50, bash 38, claim_file 15, read 9, record 8 |
| s864a00 | 136 | bash 29, wait 27, claim_file 19, inbox 9, read 8 |
| system | 13 | idle_nudge 13 |

| Signal | Count |
| --- | --- |
| claim violations | 9 |
| implicit claims (shell writes turned into claims) | 308 |
| inputs violations | 0 |
| inputs checks | 0 |
| forge hints | 9 |
| sentinel nudges | 0 |
| idle nudges | 13 |
| per-agent cap steers | 0 |
| per-agent cap stops | 0 |
| posts | 39 |
| bash calls | 509 |

Forged tools:

- `grep_filelist` by s864a08 at 2026-09-18T16:09:29.149Z (bash; called 0 times)
- `icat_extract` by s864a08 at 2026-09-18T16:09:29.176Z (bash; called 1 time)
- `catalog_grep` by s864a02 at 2026-09-18T16:10:29.359Z (python3; called 11 times)
- `fve_metadata` by s864a05 at 2026-09-18T17:23:46.009Z (python3; called 1 time)
- `aescrypt_v2_decrypt` by s864a02 at 2026-09-18T17:25:44.842Z (python3; called 0 times)

Bash leading commands (top 10):

| Command | Runs |
| --- | --- |
| `python3` | 92 |
| `grep` | 63 |
| `icat` | 42 |
| `ls` | 37 |
| `rg` | 31 |
| `export` | 29 |
| `cat` | 10 |
| `mkdir` | 9 |
| `which` | 9 |
| `find` | 6 |

## Ledger

141 entries: 89 events, 23 indicators, 29 findings (`ledger/ledger.md`).

Last 10 events in time order:

| Time (UTC) | Event | Source | By |
| --- | --- | --- | --- |
| 2023-02-22T23:40:05.000Z | Second OpenPGP key pair generated — two private keys and revocation cert created | catalog/AF-Case2.E01/p0/timeline.csv | s864a07 |
| 2023-02-22T23:40:05.000Z | GnuPG keys created in Users/IEUser/AppData/Roaming/gnupg/private-keys-v1.d/ - two protected private keys (Ed25519 signing key ECE04CCE and Curve25519 encryption key 01A2C899), both passphrase-protected | catalog/AF-Case2.E01/p0/bodyfile.txt, inodes 126846, 126847 | s864a08 |
| 2023-02-22T23:42:16.000Z | gpg.exe executed — GPG encryption/signing activity; random_seed generated | catalog/AF-Case2.E01/p0/timeline.csv | s864a07 |
| 2023-02-22T23:42:16.585Z | gpg.exe last executed (prefetch run_count=19) against IEUser gnupg pubring.kbx — OpenPGP activity around Keys.txt | Windows/Prefetch/GPG.EXE-9397A9C0.pf inode 126766 | s864a03 |
| 2023-02-22T23:42:31.000Z | Keys.txt created in IEUser/Downloads — encrypted message using GPG asymmetric encryption | catalog/AF-Case2.E01/p0/timeline.csv | s864a07 |
| 2023-02-22T23:42:31.000Z | Keys.txt (PGP-encrypted message) created in Users/IEUser/Downloads/ - encrypted to two GPG keys | catalog/AF-Case2.E01/p0/bodyfile.txt, inode 126939 | s864a08 |
| 2023-02-22T23:42:37.000Z | Keys.txt (PGP-encrypted message, 443 bytes) created in IEUser\Downloads | Users/IEUser/Downloads/Keys.txt | s864a04 |
| 2023-02-22T23:43:19.000Z | Jane created a Town Square post wx5cwg49kj8utkd1kjme1nfarh (api_posts_create); body is not in Edge unread cache, $LogFile, WebCacheV01.dat, or IndexedDB.edb. | Edge DOM store www.ccdfir XML (Rudder analytics queue) | s864a01 |
| 2023-02-22T23:44:56.000Z | 7zG.exe executed — referenced ProgramData/Starwars/R2D2.7z, may be a compressed copy of the FVE VHD | work/artifacts.md by s864a03 | s864a07 |
| 2023-02-22T23:44:56.647Z | 7zG.exe executed (prefetch run_count=3) and referenced ProgramData\Starwars\R2D2.7z | Windows/Prefetch/7ZG.EXE-2A7D43BC.pf inode 84423 | s864a03 |

## Work

| File | Size |
| --- | --- |
| `work/artifacts.md` | 16.3 KB |
| `work/bitlocker.md` | 8.7 KB |
| `work/caches.md` | 13.2 KB |
| `work/disk.md` | 13.7 KB |
| `work/recovery.md` | 10.7 KB |
| `work/report.md` | 18.5 KB |
| `work/timeline.md` | 7.5 KB |
| `work/user-activity.md` | 11.7 KB |
| `work/extracted/$LogFile` | 54.7 MB |
| `work/extracted/AESCrypt_Install_Notes.txt` | 623 B |
| `work/extracted/BitLocker_Management.evtx` | 68.0 KB |
| `work/extracted/BitLocker_Recovery_Key.lnk` | 792 B |
| `work/extracted/BitLocker_Recovery_Key.txt` | 1.3 KB |
| `work/extracted/BitLocker_Recovery_Key_EBB0BD7C.TXT` | 1.3 KB |
| `work/extracted/ConsoleHost_history.txt` | 601 B |
| `work/extracted/DeceiveYou.png` | 5.2 KB |
| `work/extracted/DeceiveYou_ocr.txt` | 51 B |
| `work/extracted/IndexedDB.edb` | 1.5 MB |
| `work/extracted/John_0x61BE50C1_public.asc` | 661 B |
| `work/extracted/Keys.txt` | 443 B |
| `work/extracted/NTUSER.DAT` | 1.3 MB |
| `work/extracted/R2D2.vhd` | 100.0 MB |
| `work/extracted/R2D2_Documents.vhd` | 100.0 MB |
| `work/extracted/R2D2_E.lnk` | 348 B |
| `work/extracted/R2D2_partition.raw` | 97.0 MB |
| `work/extracted/R2D2_vhd.lnk` | 809 B |
| `work/extracted/README.txt` | 97 B |
| `work/extracted/README.txt.aes` | 418 B |
| `work/extracted/README.txt.lnk` | 640 B |
| `work/extracted/SYSTEM` | 10.5 MB |
| `work/extracted/UsnJrnl_J.bin` | 95.8 MB |
| `work/extracted/WebCacheV01.dat` | 23.0 MB |
| `work/extracted/categories_cache.json` | 1.0 KB |
| `work/extracted/channels_cache.json` | 1.1 KB |
| `work/extracted/gpg_key_01A2C899.key` | 429 B |
| `work/extracted/gpg_key_ECE04CCE.key` | 422 B |
| `work/extracted/hives/Amcache.hve` | 1.3 MB |
| `work/extracted/hives/NTUSER.DAT` | 1.3 MB |
| `work/extracted/hives/SAM` | 64.0 KB |
| `work/extracted/hives/SECURITY` | 64.0 KB |
| `work/extracted/hives/SOFTWARE` | 69.0 MB |
| `work/extracted/hives/SYSTEM` | 10.5 MB |
| `work/extracted/hives/UsrClass.dat` | 3.3 MB |
| `work/extracted/jumplists/16d2984ec390e33.automaticDestinations-ms` | 3.5 KB |
| `work/extracted/jumplists/1b4dd67f29cb1962.automaticDestinations-ms` | 4.0 KB |
| `work/extracted/jumplists/4975d6798a8bdf66.automaticDestinations-ms` | 2.5 KB |
| `work/extracted/jumplists/590aee7bdd69b59b.customDestinations-ms` | 5.3 KB |
| `work/extracted/jumplists/5a794779d13c9e5e.automaticDestinations-ms` | 1.5 KB |
| `work/extracted/jumplists/5f7b5f1e01b83767.automaticDestinations-ms` | 10.5 KB |
| `work/extracted/jumplists/606a33f5a27b57d4.automaticDestinations-ms` | 1.5 KB |
| `work/extracted/jumplists/9b9cdc69c1c24e2b.automaticDestinations-ms` | 6.5 KB |
| `work/extracted/jumplists/9d1f905ce5044aee.customDestinations-ms` | 1.6 KB |
| `work/extracted/jumplists/a52b0784bd667468.automaticDestinations-ms` | 3.0 KB |
| `work/extracted/jumplists/cb05cc8c5a282971.automaticDestinations-ms` | 1.5 KB |
| `work/extracted/jumplists/e4ea035065b5789a.automaticDestinations-ms` | 1.5 KB |
| `work/extracted/jumplists/f01b4d95cf55d32a.automaticDestinations-ms` | 9.5 KB |
| `work/extracted/kleopatra_emaildefaults` | 63 B |
| `work/extracted/kleopatrarc` | 925 B |
| `work/extracted/kleopatrastaterc` | 298 B |
| `work/extracted/lnk/AESCrypt_v310_x64.lnk` | 1.0 KB |
| `work/extracted/lnk/BitLocker_Recovery_Key.lnk` | 792 B |
| `work/extracted/lnk/DeceiveYou.png.lnk` | 478 B |
| `work/extracted/lnk/John_public.asc.lnk` | 684 B |
| `work/extracted/lnk/Keys.txt.lnk` | 628 B |
| `work/extracted/lnk/Kleopatra.lnk` | 2.1 KB |
| `work/extracted/lnk/R2D2.vhd.lnk` | 809 B |
| `work/extracted/lnk/R2D2_E.lnk` | 348 B |
| `work/extracted/lnk/README.txt.lnk` | 640 B |
| `work/extracted/lnk/Starwars.lnk` | 644 B |
| `work/extracted/lnk/eula.lnk` | 896 B |
| `work/extracted/mattermost_nps_bundle.js` | 358.9 KB |
| `work/extracted/me_cache.json` | 628 B |
| `work/extracted/posts_cache1.json` | 59 B |
| `work/extracted/posts_cache2.json` | 59 B |
| `work/extracted/posts_cache3.json` | 59 B |
| `work/extracted/posts_cache4.json` | 59 B |
| `work/extracted/prefetch/7Z2201-X64.EXE-9C0F0D87.pf` | 13.1 KB |
| `work/extracted/prefetch/7ZG.EXE-2A7D43BC.pf` | 11.3 KB |
| `work/extracted/prefetch/BACKGROUNDTASKHOST.EXE-F30DA8E2.pf` | 9.1 KB |
| `work/extracted/prefetch/BDEUISRV.EXE-1E495B67.pf` | 6.9 KB |
| `work/extracted/prefetch/BDEUNLOCK.EXE-C5D4009E.pf` | 15.7 KB |
| `work/extracted/prefetch/BGINFO.EXE-7A859B68.pf` | 17.5 KB |
| `work/extracted/prefetch/BITLOCKERWIZARDELEV.EXE-E4CCF1B7.pf` | 9.5 KB |
| `work/extracted/prefetch/CMD.EXE-89305D47.pf` | 3.9 KB |
| `work/extracted/prefetch/COMPMGMTLAUNCHER.EXE-0BF80059.pf` | 15.5 KB |
| `work/extracted/prefetch/DEFRAG.EXE-738093E8.pf` | 3.6 KB |
| `work/extracted/prefetch/DIRMNGR.EXE-13299201.pf` | 5.4 KB |
| `work/extracted/prefetch/DLLHOST.EXE-6E215B0C.pf` | 12.5 KB |
| `work/extracted/prefetch/FVENOTIFY.EXE-0C4FF5DD.pf` | 4.6 KB |
| `work/extracted/prefetch/GNUPG-W32-2.4.0_20221216-BIN.-59B595C3.pf` | 14.1 KB |
| `work/extracted/prefetch/GPG-AGENT.EXE-6457DE3C.pf` | 6.1 KB |
| `work/extracted/prefetch/GPG-CONNECT-AGENT.EXE-BC0B6587.pf` | 5.2 KB |
| `work/extracted/prefetch/GPG.EXE-9397A9C0.pf` | 6.7 KB |
| `work/extracted/prefetch/GPG4WIN-4.1.0.EXE-B0AF8464.pf` | 18.0 KB |
| `work/extracted/prefetch/GPGCONF.EXE-3FD39C96.pf` | 5.3 KB |
| `work/extracted/prefetch/GPGME-W32SPAWN.EXE-19A5FED7.pf` | 3.3 KB |
| `work/extracted/prefetch/GPGSM.EXE-800E8988.pf` | 5.6 KB |
| `work/extracted/prefetch/HXD.EXE-6EB5CCA9.pf` | 11.3 KB |
| `work/extracted/prefetch/HXDSETUP.EXE-122515E4.pf` | 6.4 KB |
| `work/extracted/prefetch/KEYBOXD.EXE-11DE4930.pf` | 5.1 KB |
| `work/extracted/prefetch/KLEOPATRA.EXE-C82479BC.pf` | 31.8 KB |
| `work/extracted/prefetch/MMC.EXE-94CB0423.pf` | 32.1 KB |
| `work/extracted/prefetch/MSIEXEC.EXE-B5AFA339.pf` | 28.5 KB |
| `work/extracted/prefetch/MSIEXEC.EXE-F3744DFD.pf` | 7.0 KB |
| `work/extracted/prefetch/NOTEPAD.EXE-EB1B961A.pf` | 9.9 KB |
| `work/extracted/prefetch/PICKERHOST.EXE-93018817.pf` | 23.8 KB |
| `work/extracted/prefetch/PINENTRY.EXE-FCC0D062.pf` | 18.3 KB |
| `work/extracted/prefetch/POWERSHELL.EXE-3E7086C1.pf` | 24.4 KB |
| `work/extracted/prefetch/POWERSHELL.EXE-59FC8F3D.pf` | 74.5 KB |
| `work/extracted/prefetch/REG.EXE-26976709.pf` | 2.7 KB |
| `work/extracted/prefetch/RUNDLL32.EXE-0F4E6EC8.pf` | 4.3 KB |
| `work/extracted/prefetch/RUNDLL32.EXE-2BAF368C.pf` | 4.3 KB |
| `work/extracted/prefetch/RUNDLL32.EXE-61F8EC7A.pf` | 4.3 KB |
| `work/extracted/prefetch/SCDAEMON.EXE-2671F944.pf` | 5.9 KB |
| `work/extracted/prefetch/SCP.EXE-BCA37F35.pf` | 3.2 KB |
| `work/extracted/prefetch/SDELETE.EXE-257E3D6D.pf` | 4.5 KB |
| `work/extracted/prefetch/SETUP.EXE-BD5701D0.pf` | 9.0 KB |
| `work/extracted/prefetch/VDS.EXE-AD27F0DC.pf` | 7.3 KB |
| `work/extracted/prefetch/VDSLDR.EXE-85F9A1C6.pf` | 4.2 KB |
| `work/extracted/private-key-1.key` | 429 B |
| `work/extracted/private-key-2.key` | 422 B |
| `work/extracted/pubring.kbx` | 0 B |
| `work/extracted/pubring_orig.kbx` | 1.9 KB |
| `work/extracted/random_seed` | 600 B |
| `work/extracted/revocation-7F593AC7.rev` | 1.2 KB |
| `work/extracted/revocation-E93BD5BD.rev` | 1.2 KB |
| `work/extracted/s864a02/AESCrypt.dll` | 136.0 KB |
| `work/extracted/s864a02/ActivitiesCache.db` | 1.0 MB |
| `work/extracted/s864a02/IndexedDB.edb` | 1.5 MB |
| `work/extracted/s864a02/README.txt.aes` | 418 B |
| `work/extracted/s864a02/WebCacheV01.dat` | 23.0 MB |
| `work/extracted/s864a02/aescrypt.exe` | 151.5 KB |
| `work/extracted/s864a02/categories2_4V3RWSG8.json` | 1.0 KB |
| `work/extracted/s864a02/channel_xoo6bhdq.json` | 2 B |
| `work/extracted/s864a02/channels2_W800YVVL.json` | 1.1 KB |
| `work/extracted/s864a02/client3_W800YVVL.json` | 6.1 KB |
| `work/extracted/s864a02/client4_W800YVVL.json` | 22 B |
| `work/extracted/s864a02/me_C3CQOIW2.json` | 628 B |
| `work/extracted/s864a02/members2_ETVG1HOQ.json` | 196 B |
| `work/extracted/s864a02/members2_W800YVVL.json` | 1.2 KB |
| `work/extracted/s864a02/ping1_ETVG1HOQ.json` | 154 B |
| `work/extracted/s864a02/ping2_ETVG1HOQ.json` | 154 B |
| `work/extracted/s864a02/posts1_4V3RWSG8.json` | 59 B |
| `work/extracted/s864a02/posts1_C3CQOIW2.json` | 59 B |
| `work/extracted/s864a02/posts1_ETVG1HOQ.json` | 59 B |
| `work/extracted/s864a02/posts2_4V3RWSG8.json` | 59 B |
| `work/extracted/s864a02/preferences_W800YVVL.json` | 619 B |
| `work/extracted/s864a02/spartan.edb` | 2.0 MB |
| `work/extracted/s864a02/stats1_4V3RWSG8.json` | 97 B |
| `work/extracted/s864a02/status2_4V3RWSG8.json` | 107 B |
| `work/extracted/s864a02/teams1_4V3RWSG8.json` | 2 B |
| `work/extracted/s864a02/teams2_ETVG1HOQ.json` | 332 B |
| `work/extracted/s864a02/town-square.htm` | 3.0 KB |
| `work/extracted/s864a02/unread1_C3CQOIW2.json` | 74 B |
| `work/extracted/s864a02/unread3_C3CQOIW2.json` | 6.1 KB |
| `work/extracted/s864a02/users_4V3RWSG8.json` | 1.7 KB |
| `work/extracted/s864a02/webapp2_C3CQOIW2.json` | 361 B |
| `work/extracted/s864a02/www.ccdfir.xml` | 28.4 KB |
| `work/extracted/spartan.edb` | 2.0 MB |
| `work/extracted/stats_cache.json` | 97 B |
| `work/extracted/status_cache.json` | 107 B |
| `work/extracted/teams_cache.json` | 2 B |
| `work/extracted/tofu.db` | 48.0 KB |
| `work/extracted/town-square-cached.htm` | 3.0 KB |
| `work/extracted/trustdb.gpg` | 1.4 KB |
| `work/extracted/unread3_C3CQOIW2.json` | 6.1 KB |
| `work/extracted/unread_cache.json` | 74 B |
| `work/extracted/users_cache.json` | 1.7 KB |
| `work/extracted/webapp_cache.json` | 361 B |
| `work/extracted/www.ccdfir_DOMStore.xml` | 28.4 KB |
| `work/s864a00/` (scratch of s864a00) | 9 files, 200.0 MB |
| `work/s864a01/` (scratch of s864a01) | 15 files, 94.9 MB |
| `work/s864a02/` (scratch of s864a02) | 1 files, 97 B |
| `work/s864a03/` (scratch of s864a03) | 9 files, 352.7 KB |
| `work/s864a04/` (scratch of s864a04) | 0 files, 0 B |
| `work/s864a05/` (scratch of s864a05) | 0 files, 0 B |
| `work/s864a06/` (scratch of s864a06) | 15 files, 13.3 KB |
| `work/s864a08/` (scratch of s864a08) | 0 files, 0 B |

## Custody

Inputs from `/Users/halilozturkci/DFIR/SampleCases/AliHadi/challenge-09-encrypt-them-all`, copied 2026-09-18T16:04:29Z: 2 files, 7.4 GB; enforcement asked auto, kickoff guard seatbelt.

| Input | Bytes | SHA-256 |
| --- | --- | --- |
| `inputs/AF-Case2.E01` | 7,912,229,414 | `d35a3bdfa1c12198f16fa2a98fa5c90a0ae408e0d983ba46213bb9bafcb1d6b0` |
| `inputs/CASE.md` | 1,721 | `b340260cb30ccc5e070f01d84932c35d888a4655f4121542f101b45a227c2763` |

No inputs check is on the trace: nothing verified the inputs at the end of the run.

Toolbox (dfir): 12 present — mmls (The Sleuth Kit ver 4.15.0), fls (The Sleuth Kit ver 4.15.0), icat (The Sleuth Kit ver 4.15.0), mactime (The Sleuth Kit ver 4.15.0), vol (Volatility 3 Framework 2.28.2), regipy-dump (6.3.0), evtx_dump (python-evtx ok), yara (4.5.8), exiftool (12.92), sqlite3 (3.54.0 2026-04-09 12:25:13 8fa8248e303219400c646a885e36dfc52eae33d83f4412e3f369b2be5373aapl (64-bit)), strings (error: /Library/Developer/CommandLineTools/usr/bin/strings: unknown flag: --version), python3 (Python 3.12.1); 0 missing.

Evidence catalog: 1 disk image(s), 0 memory image(s), 5 catalog file(s).
