# Timeline — Case AH-C09 "Encrypt Them All"

Merged from `ledger/ledger.md` (125+ entries: 72+ events, 19 IOCs, 15+ findings).
All times UTC. Evidence paths and inode numbers from `inputs/AF-Case2.E01`.

## Jane's Encryption Activity Timeline

| # | Time (UTC) | Event | Evidence |
|---|-----------|-------|----------|
| 1 | 2023-02-20 23:24 | PowerShell: disable Windows Defender (exclude C:\, disable realtime), disable auto-updates, add `192.168.137.129 www.ccdfir.local` to hosts | ConsoleHost_history.txt (inode 88493), hosts file (inode 42564) |
| 2 | 2023-02-20 23:32 | First Mattermost login — Edge opens `https://www.ccdfir.local/login` | ActivitiesCache.db (inode 84030) |
| 3 | 2023-02-22 15:40 | gpg4win-4.1.0.exe (28 MB) downloaded via VMware Drag-and-Drop | inode 62487 (Downloads) |
| 4 | 2023-02-22 15:41 | AESCrypt_v310_x64.zip (1.1 MB) downloaded via VMware Drag-and-Drop | inode 62486 (Downloads) |
| 5 | 2023-02-22 17:21:42 | **Jane reveals AES password in Mattermost**: "John, the password will be 'StarWars!' with no quotes" | Edge cache unread[3].json (inode 126728) |
| 6 | 2023-02-22 17:24:32 | Jane uploads README.txt.aes (418 bytes) to Mattermost Town Square | Edge cache unread[3].json (inode 126728) |
| 7 | 2023-02-22 17:46:09 | Jane posts R2D2 hint: "the password for the volume is within the volume :D" | Edge cache unread[3].json (inode 126728) |
| 8 | 2023-02-22 18:40 | Jane opens Mattermost Town Square in Edge | ActivitiesCache.db (inode 84030) |
| 9 | 2023-02-22 18:43 | AESCrypt ZIP extracted to `Downloads/AESCrypt_v310_x64/` | inode 84440 (directory) |
| 10 | 2023-02-22 18:47 | Gpg4win/GnuPG suite installed to Program Files (x86) | Multiple DLLs, inodes 125217–125393 |
| 11 | 2023-02-22 18:54 | AESCrypt installed to `Program Files/AESCrypt/` | aescrypt.exe (inode 126718), AESCrypt32.exe (126716), AESCrypt.dll (126717) |
| 12 | 2023-02-22 19:46:01 | README.txt created as "New Text Document.txt" in Documents (MFT 27936-3) | $UsnJrnl:$J (inode 80499) |
| 13 | 2023-02-22 19:46:04 | Renamed to README.txt; Recent LNK created | $UsnJrnl:$J, README.txt.lnk (inode 27941) |
| 14 | 2023-02-22 20:20:06 | **README.txt content written** (DATA_EXTEND) — plaintext composed | $UsnJrnl:$J (inode 80499) |
| 15 | 2023-02-22 20:21:17 | **README.txt.aes created** — AES Crypt v3.10 via Explorer context menu (AESCrypt.dll), password "StarWars!" | inode 126755, 418 bytes, AES version 2 |
| 15b |  | **Decrypted**: "It is a very well known quote and can be found here: https://www.youtube.com/watch?v=66Ux1D9MDOk" | Decrypted by s864a00, SHA256 `32282626…` |
| 16 | 2023-02-22 20:21:25 | **README.txt deleted** — MFT entry reused by Edge cache at 20:23:37 | $UsnJrnl:$J (inode 80499) |
| 17 | 2023-02-22 20:25 | GnuPG user profile initialized (trustdb, pubring, sockets) | inodes 126762–126784 |
| 18 | 2023-02-22 20:26:52 | **vds.exe executed** — Virtual Disk Service attaches R2D2.vhd | Prefetch (s864a03) |
| 19 | 2023-02-22 20:28:10 | **R2D2.vhd created** in Documents (100 MB, unencrypted NTFS, volume name "R2D2") | inode 126800, SHA256 `06d831eb…` |
| 20 | 2023-02-22 20:28:49 | John posts in Mattermost: "Jane, please see my public key" | Edge cache unread[3].json (inode 126728) |
| 21 | 2023-02-22 20:28:58 | **John uploads `John_0x61BE50C1_public.asc`** to Mattermost | Edge cache unread[3].json (inode 126728) |
| 22 | 2023-02-22 20:34:08 | Starwars folder created in ProgramData | Starwars.lnk (inode 126756) |
| 22 | 2023-02-22 20:34:09 | **R2D2.vhd cloned** to `ProgramData/Starwars/R2D2.vhd` | inode 126812, SHA256 `8eeec4b6…` |
| 23 | 2023-02-22 20:34:28 | **DeceiveYou.png written inside R2D2 VHD** — text: "Your eyes can deceive you! R2D2 has been cloned :P" | VHD inode 39, 5324 bytes, SHA256 `a77e68f5…` |
| 24 | 2023-02-22 20:34:31 | **R2D2 VHD mounted as drive E:** | R2D2 (E).lnk (inode 126818) |
| 25 | 2023-02-22 20:42:13 | **BitLockerWizardElev.exe executed** — BitLocker enabled on Starwars R2D2 (drive E:) | Prefetch (inode 126823), event log (inode 27913) |
| 26 | 2023-02-22 20:44:10 | **BitLocker Recovery Key saved**: Identifier `EBB0BD7C-DB64-47F5-9A3B-03939F6E8F76`, Key `011594-477554-129965-535183-310288-707949-274901-523688` | inode 126830, 1,348 bytes |
| 27 | 2023-02-22 20:47:40 | **Starwars R2D2.vhd BitLocker encryption finalized** (-FVE-FS- boot sector, AES-XTS 128) | inode 126812, FVE metadata at offset 35586048 |
| 28 | 2023-02-22 20:47:26 | **bdeunlock.exe executed** (2 runs) — BitLocker drive unlock attempt on R2D2 E: | Prefetch (inode 126839, s864a03) |
| 29 | 2023-02-22 20:50:53 | E01 forensic image acquired (FTK Imager ADI4.7.1.2) | ewfinfo on AF-Case2.E01 |
| 30 | 2023-02-22 20:51:12 | First OpenPGP key pair generated (revocation E93BD5BD…) | inode 126849 |
| 31 | 2023-02-22 23:31:21 | **John's public key downloaded** to Downloads | inode 126919, Zone.Identifier ADS |
| 32 | 2023-02-22 23:39:26 | Kleopatra imports/manages John's key (fingerprint `9D3DD605…61BE50C1`) | kleopatrarc (inode 126787) |
| 33 | 2023-02-22 23:40:03 | **pinentry.exe executed** (10 runs) — GPG passphrase prompts for key generation | Prefetch (s864a03) |
| 34 | 2023-02-22 23:40:05 | **Jane's GPG key pair generated**: Ed25519 + Curve25519, fingerprint `7F593AC7…B52B04AD` | inodes 126846, 126847, 126892 |
| 35 | 2023-02-22 23:42:16 | gpg.exe executed — encryption/signing activity | Prefetch GPG.EXE (inode 126766) |
| 36 | 2023-02-22 23:42:31 | **Keys.txt created** in Downloads (443 bytes) — PGP-encrypted to Jane + John | inode 126939 |
| 37 | 2023-02-22 23:43:19 | **Keys.txt uploaded** to Mattermost Town Square (post `wx5cwg49…`) | IndexedDB.edb (inode 82751) |
| 38 | 2023-02-22 23:44:56 | **7zG.exe executed** — may reference R2D2.7z compressed copy of FVE VHD | Prefetch (inode 84423, s864a03) |

## How the Three Parts Connect

1. **Lost in Space (Part 1)**: Jane set up Mattermost at `www.ccdfir.local` (hosts redirect to 192.168.137.129). She told John the AES password "StarWars!" in Town Square, then created README.txt, encrypted it with AESCrypt v3.10 (password "StarWars!"), uploaded the `.aes` file to Mattermost, and deleted the plaintext. The README plaintext was later recovered from Edge cache (Mattermost `unread[3].json`, inode 126728) — John's Town Square view preserved the communication.

2. **Do Not Be Deceived! (Part 2)**: Jane created two 100 MB VHDs. The **Documents R2D2.vhd** is an unencrypted "decoy" containing DeceiveYou.png with the message "Your eyes can deceive you! R2D2 has been cloned :P". The **Starwars R2D2.vhd** is the BitLocker-encrypted clone (AES-XTS 128). The recovery key was saved to Documents. The BitLocker password hint Jane gave ("the password for the volume is within the volume :D") points to the PNG text inside.

3. **Your Focus Determines Your Reality (Part 3)**: Jane generated her GPG key pair, imported John's public key from Mattermost, encrypted Keys.txt to both keys, and uploaded the encrypted message back to Mattermost. This was the culmination of the encrypted communication exercise.

## Summary

Jane (IEUser) conducted a staged encryption exercise across three methods — symmetric (AES), full-disk (BitLocker), and asymmetric (GPG) — using Mattermost at `ccdfir.local` as the covert communication channel with John. All three encrypted artefacts (README.txt.aes, Starwars R2D2.vhd, Keys.txt) were recovered from the forensic image. AES password "StarWars!" and communication context were recovered from Edge browser cache; BitLocker recovery key was saved on disk; GPG private keys for Jane were extracted from her GnuPG keyring.