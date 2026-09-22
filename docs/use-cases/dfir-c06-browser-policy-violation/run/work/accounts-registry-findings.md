# Accounts and event log findings

## Scope and sources

This note covers local accounts, profiles, logons, and relevant Security/System event log activity from the assigned seat.

Primary evidence extracted from `inputs/Browser_Policy_Violation.E01`:

- `Windows/System32/config/SAM` (inode `43569-128-4`) → `work/extracted/accounts/SAM` (`SHA-256 1c9f4e45f0c565d01e9ae7349c86227f4d3398a39e6d60d0189f9bcb20842e0a`)
- `Windows/System32/config/SECURITY` (inode `43571-128-4`) → `work/extracted/accounts/SECURITY` (`SHA-256 b60036ee89c1c807dd4a17f59a8ff11548efd2dba9b9612acc36f7a920843e9b`)
- `Windows/System32/config/SYSTEM` (inode `43894-128-4`) → `work/extracted/accounts/SYSTEM` (`SHA-256 298ed523751be46748fa09080fc18f91cfab6273324e84400b4f4ce26de47977`)
- `Windows/System32/config/SOFTWARE` (inode `48452-128-4`) → `work/extracted/accounts/SOFTWARE` (`SHA-256 df43513d354aa78c3c911972ab1b1ff365c6c50015520f5be8ae7c14fee24133`)
- `Users/IEUser/NTUSER.DAT` (inode `87325-128-4`) → `work/extracted/accounts/IEUser.NTUSER.DAT` (`SHA-256 08d6332f1e058ec25066fbd9edbfc403b9ee97f9098fe557816e75a225b4d82d`)
- `Users/sshd_server/NTUSER.DAT` (inode `90819-128-4`) → `work/extracted/accounts/sshd_server.NTUSER.DAT` (`SHA-256 12fb5a40c31f35d39f78d0c3d38897d0ea624e0c1535e0720cbfc94240596404`)
- `Windows/System32/winevt/Logs/Security.evtx` (inode `83684-128-4`) → `work/extracted/accounts/Security.evtx` (`SHA-256 00f47390a34ec219efe849c8ad4ed48ef5ea59d368295a91cf694830f6a73a07`)
- `Windows/System32/winevt/Logs/System.evtx` (inode `83682-128-4`) → `work/extracted/accounts/System.evtx` (`SHA-256 eb69ccf883648ec69924a22f5596d1bbf36c2aac4a44c2fe2c687aa31ec7aab9`)
- `Windows/System32/winevt/Logs/Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx` (inode `83693-128-4`) → `work/extracted/accounts/Microsoft-Windows-TerminalServices-LocalSessionManager-Operational.evtx` (`SHA-256 73376b5befd6404abfdf26a4ca9fcb245d6c283cb1c88ea693f7fab905783424`)

Derived analyst outputs:

- `work/s881001/sam_summary.json`
- `work/s881001/profilelist.json`
- `work/s881001/security_account_events.csv`
- `work/s881001/target_events.csv`
- `work/s881001/lsm_sessions.csv`
- `work/s881001/system_7045.csv`

## System identity from registry

Current system identity in the registry:

- Computer name: `MSEDGEWIN10` from `\ControlSet001\Control\ComputerName\ComputerName\ComputerName` in `work/extracted/accounts/SYSTEM`.
- Time zone: `Pacific Standard Time` with `ActiveTimeBias=480` from `\ControlSet001\Control\TimeZoneInformation` in `work/extracted/accounts/SYSTEM`.
- Windows edition: `Windows 10 Enterprise Evaluation`, Release `1803`, Build `17134`, `BuildLabEx 17134.1.amd64fre.rs4_release.180410-1804`, from `\Microsoft\Windows NT\CurrentVersion` in `work/extracted/accounts/SOFTWARE`.
- Install date recorded in SOFTWARE: Unix epoch `1524686446` = `2018-04-25T20:00:46Z` from `InstallDate` in `\Microsoft\Windows NT\CurrentVersion`.

Note: early Security/System events use computer name `IEUSER-CI17VQGT`, while current registry state is `MSEDGEWIN10`, indicating the system was renamed during setup/provisioning. Example: Security event record `42` still reports `Computer=IEUSER-CI17VQGT`, while later account activity records report `MSEDGEWIN10` and the current SYSTEM hive confirms `MSEDGEWIN10`.

## Local accounts and current profile state

Current/local-account state from the SAM hive (`work/s881001/sam_summary.json`) and profile mappings from `work/s881001/profilelist.json`:

| RID | Account | Current state from SAM | Profile evidence | Last login / use evidence |
| --- | --- | --- | --- | --- |
| 500 | Administrator | Disabled; password last set `2018-04-25T20:00:38.155258Z` | No separate user profile in `ProfileList` | No successful logon in current SAM summary |
| 501 | Guest | Disabled | No separate user profile | No successful logon in current SAM summary |
| 503 | DefaultAccount | Disabled | No separate user profile | No successful logon in current SAM summary |
| 504 | WDAGUtilityAccount | Disabled | No separate user profile | Created during setup; no successful logon in current SAM summary |
| 1000 | IEUser | Enabled; password-never-expires flag; `login_count=11` | `S-1-5-21-...-1000` → `C:\Users\IEUser` | SAM last login `2018-11-25T18:24:09.849785Z`; interactive logons and LocalSessionManager sessions corroborate use |
| 1002 | sshd | Disabled; password-never-expires flag; `login_count=0` | No profile listed in `ProfileList` | Created by IEUser; no successful logon seen in SAM |
| 1003 | sshd_server | Enabled; password-never-expires flag; `login_count=6` | `S-1-5-21-...-1003` → `C:\Users\sshd_server` | SAM last login `2018-11-25T18:24:10.224581Z`; Security 4624 type 5 logons corroborate service activity |

Important negative finding: `defaultuser0` appears in Security and LocalSessionManager events but does **not** appear in the current SAM user list or `ProfileList`, consistent with that account being transient and later deleted.

## Account creation, deletion, and group changes

The clearest account-management sequence in Security is:

1. `IEUser` was created on `2018-04-25 20:00:38.103165+00:00` (Security event `4720`, record `190`) and was then added to:
   - the local Users group on `2018-04-25 20:00:38.107899+00:00` (Security `4732`, record `193`), and
   - the local Administrators group on `2018-04-25 20:00:38.140976+00:00` (Security `4732`, record `200`).
2. `defaultuser0` was created on `2018-04-25 20:00:40.199394+00:00` (Security `4720`, record `220`), added to Users (record `221`) and Administrators (record `230`), then later disabled/removed and deleted by `IEUser`:
   - disabled on `2018-04-25 20:01:16.496645+00:00` (Security `4725`, record `387`),
   - removed from Administrators on `2018-04-25 20:01:16.500612+00:00` (Security `4733`, record `389`),
   - removed from Users on `2018-04-25 20:02:08.920246+00:00` (Security `4733`, record `509`),
   - removed from group SID `...-513` on `2018-04-25 20:02:08.921658+00:00` (Security `4729`, record `510`),
   - deleted on `2018-04-25 20:02:08.922426+00:00` (Security `4726`, record `511`).
3. `IEUser` created `sshd` on `2018-04-25 20:06:32.487247+00:00` (Security `4720`, record `762`) and added it to Users on `2018-04-25 20:06:32.492912+00:00` (Security `4732`, record `764`).
4. `IEUser` created `sshd_server` on `2018-04-25 20:06:37.029366+00:00` (Security `4720`, record `779`), enabled it (Security `4722`, record `780`), set/reset its password (Security `4724`, record `782`), added it to Users (Security `4732`, record `783`), and then added it to Administrators on `2018-04-25 20:06:37.453815+00:00` (Security `4732`, record `787`).

These events are summarized in `work/s881001/security_account_events.csv` and were recorded into `ledger/ledger.md`.

## Logon and activity windows

### defaultuser0

`defaultuser0` had a short local interactive session corroborated by both Security 4624 and LocalSessionManager records:

- session creation/connection: `2018-04-25 20:00:48.851686+00:00` to `2018-04-25 20:00:49.300167+00:00` (LocalSessionManager records `30`-`33`, session `1`, address `LOCAL` in `work/s881001/lsm_sessions.csv`)
- disconnect/logoff: `2018-04-25 20:01:16.998293+00:00` and `2018-04-25 20:01:17.122295+00:00` (LocalSessionManager records `34` and `38`)
- Security also records successful interactive 4624 logons for `defaultuser0` at records `234` and `355`, and logoff events `4634` record `348` and `4647` record `390`.

### IEUser

`IEUser` is the primary interactive user account.

- First observed successful interactive logon: `2018-04-25 20:01:17.423159+00:00` (Security `4624`, record `399`, logon type `2`, workstation `MSEDGEWIN10`, source `127.0.0.1`; see `work/s881001/target_events.csv`).
- First LocalSessionManager local session start: `2018-04-25 20:01:17.949211+00:00` (event `21`, record `41`, address `LOCAL`; see `work/s881001/lsm_sessions.csv`).
- Last SAM-recorded login: `2018-11-25T18:24:09.849785Z` (`work/s881001/sam_summary.json`).
- Last observed LocalSessionManager session start: `2018-11-25 18:24:10.076000+00:00` (event `21`, record `97`).
- Last observed LocalSessionManager session end in the extracted log: `2018-11-25 18:38:11.289692+00:00` (event `23`, record `99`).

Observed local session windows for `IEUser` from `work/s881001/lsm_sessions.csv`:

| Start UTC | End UTC | Evidence |
| --- | --- | --- |
| 2018-04-25 20:01:17.949211 | 2018-04-25 20:01:41.058706 | LSM events 21/23, records 41/44 |
| 2018-04-25 20:02:05.605875 | 2018-04-25 20:04:36.957495 | LSM events 21/23, records 48/51 |
| 2018-04-25 20:05:02.615435 | 2018-04-25 20:05:52.106243 | LSM events 21/23, records 55/58 |
| 2018-04-25 20:06:21.872564 | 2018-04-25 20:06:50.074997 | LSM events 21/23, records 62/65 |
| 2018-04-25 20:07:19.386993 | 2018-04-25 20:13:56.416224 | LSM events 21/23, records 69/72 |
| 2018-11-25 16:18:39.262342 | 2018-11-25 16:20:32.264221 | LSM events 21/23, records 76/79 |
| 2018-11-25 16:20:56.322004 | 2018-11-25 17:35:24.653088 | LSM events 21/23, records 83/86 |
| 2018-11-25 17:38:16.487133 | 2018-11-25 18:23:48.377428 | LSM events 21/23, records 90/92 |
| 2018-11-25 18:24:10.076000 | 2018-11-25 18:38:11.289692 | LSM events 21/23, records 97/99 |

Security event `4672` follows IEUser’s 4624 interactive logons (for example records `400`, `493`, `624`, `743`, `896`, `1121`, `1280`, `1609`, `1669`, `2021`), showing that the sessions received special privileges consistent with IEUser being a member of Administrators.

### sshd_server

`sshd_server` is not used interactively in the recovered evidence; instead it appears as a service account.

- First successful service logon: `2018-04-25 20:06:41.424400+00:00` (Security `4624`, record `806`, logon type `5`).
- Corresponding privileged logon: `2018-04-25 20:06:41.424408+00:00` (Security `4672`, record `807`).
- Last successful service logon seen: `2018-11-25 18:24:10.245815+00:00` (Security `4624`, record `2026`, logon type `5`).
- SAM corroboration: `last_login=2018-11-25T18:24:10.224581Z`, `login_count=6` (`work/s881001/sam_summary.json`).

`sshd` was created but remained disabled and has `login_count=0` in the current SAM summary.

## Service-install event relevant to account activity

System event `7045` shows installation of an SSH-related service shortly after `sshd_server` was created and elevated:

- `2018-04-25 20:06:40.941944+00:00` — Service `OpenSSH Server` installed with image path `C:\Program Files\OpenSSH\bin\cygrunsrv.exe`, start type `auto start`, account `MSEDGEWIN10\sshd_server` (System `7045`, record `377`; see `work/s881001/system_7045.csv`).

This tightly links the newly created `sshd_server` local administrator account to persistent service execution.

## Bottom-line findings for the report

1. The workstation’s current identity is `MSEDGEWIN10`, running `Windows 10 Enterprise Evaluation` (1803), with timezone `Pacific Standard Time`, from the current SYSTEM and SOFTWARE hives.
2. The main human user account is `IEUser`, a local administrator with an on-disk profile at `C:\Users\IEUser`; its recovered activity extends from first creation on `2018-04-25` to last observed session/logon activity on `2018-11-25`.
3. `defaultuser0` was a transient local administrator account created during setup, used briefly in a local session, and then deleted; it is not present in the current SAM/profile state.
4. `IEUser` created two additional accounts, `sshd` and `sshd_server`, on `2018-04-25`; `sshd_server` was added to Administrators and then used to run the `OpenSSH Server` service.
5. `sshd_server` remained present and active through the later activity date (`2018-11-25`), as shown by both SAM last-login metadata and Security service-logon events.

## Caveats

- This seat focused on registry/account state and selected event logs, not browser-profile artifacts. Browser attribution still needs corroboration from the browser, prefetch, shortcut, download, and file-provenance seats.
- The `SECURITY` hive was extracted and retained for completeness, but the strongest findings here came from SAM/SYSTEM/SOFTWARE plus Security/System/LocalSessionManager EVTX data.
