# Memory / memory-adjacent findings — s0ae902

## Scope note

There is **no standalone memory image** in this case. The read-only inputs are only `inputs/4orensics.001`, `inputs/CASE.md`, and `inputs/README.txt`, and `catalog/README.md` reports `0 memory image(s)`.

Because Volatility analysis is not possible on the provided evidence set, this seat pivoted to **memory-adjacent remote-access artifacts** and application traces recoverable from disk, especially TeamViewer logs and the TeamViewer incoming-connections register.

Evidence:
- `inputs/4orensics.001`, `inputs/CASE.md`, `inputs/README.txt` via `inputs`
- `catalog/README.md`

## 1) TeamViewer was installed for Hunter and configured as a service

TeamViewer installer artifacts show installation under Hunter's SID, service installation, firewall exceptions, and the copied `tvinfo.ini` seed file.

Key evidence:
- Source path / inode: `Users/Hunter/AppData/Local/Temp/TeamViewer/TV11Install.log` inode `88424-128-4`
- Extract: `work/extracted/memory/teamviewer_installer_log.txt`
- SHA-256: `90d2c1770ec0373c77a56547324d856c15d485369a3a5131920ab77534176817`
- Focused excerpt: `work/extracted/memory/teamviewer_install_excerpt.txt`
- SHA-256: `1b4909677b1ba955bf2157081212e919ce2ab40a803d82cd8481bf0b451e95bc`
- Command: `icat -o 0 inputs/4orensics.001 88424 > work/extracted/memory/teamviewer_installer_log.txt`

Quoted lines:
- `2016-06-20-17-57-29  User-SID:      S-1-5-21-2489440558-2754304563-710705792-1001`
- `2016-06-20-17-57-41  WriteFileChanges(INSTALL_SERVICE): Install service TeamViewer with application path C:\Program Files (x86)\TeamViewer\TeamViewer_Service.exe.`
- `2016-06-20-17-57-40  WriteFileChanges(ADD_FIREWALL_EXCEPTION): Add firewall exception Teamviewer Remote Control Application for C:\Program Files (x86)\TeamViewer\TeamViewer.exe.`
- `2016-06-20-17-57-41  WriteFileChanges(ADD_FIREWALL_EXCEPTION): Add firewall exception Teamviewer Remote Control Service for C:\Program Files (x86)\TeamViewer\TeamViewer_Service.exe.`
- `2016-06-20-17-57-42  WriteRegChanges(WRITE_STRING): Write registry value HKEY_LOCAL_MACHINE\SOFTWARE\TeamViewer\InstallationDate=2016-06-20`

Corroboration:
- `Users/Hunter/AppData/Roaming/TeamViewer/TeamViewer11_Logfile.log` inode `88509-128-4` shows:
  - `2016/06/20 17:57:41.195 ... Service install: Param:'-install'`
  - `2016/06/20 17:57:41.329 ... Service TeamViewer at "C:\Program Files (x86)\TeamViewer\TeamViewer_Service.exe" installed`
- Extract: `work/extracted/memory/teamviewer_install_service_log.txt`
- SHA-256: `86702c5eac056d084293b464509537d0032ba68666cfae66290bd0daf64276fb`
- Excerpt hash: `0664c505d474b1ba905af9c1769f22f929664505f22db23fdcf020e8a89d5b14`

## 2) TeamViewer ran under Hunter and registered host ID 543055371

The main TeamViewer log ties execution to `4orensics\hunter`, shows the host IP, and records TeamViewer ClientID `543055371`.

Key evidence:
- Source path / inode: `Program Files (x86)/TeamViewer/TeamViewer11_Logfile.log` inode `88429-128-4`
- Extract: `work/extracted/memory/teamviewer_program_log.txt`
- SHA-256: `eaccf594b5daeb04a3c76028311bb3964d62018dbd4e35d2b24ec62f31f11c94`
- Session excerpt: `work/extracted/memory/teamviewer_session_excerpt.txt`
- SHA-256: `67dd3a378dddb90def42dea49301aebcf81d63eb5a675ad1ee768ad47a427571`
- Command: `icat -o 0 inputs/4orensics.001 88429 > work/extracted/memory/teamviewer_program_log.txt`

Quoted lines:
- `Start:              2016/06/20 17:57:45.485 (UTC-8:00)`
- `IP:                 10.0.2.15`
- `CTerminalServer::StartGUIProcess() GUI process 4776 started for user 4orensics\hunter in session 1`
- `CKeepAliveClient::HandleRegisterUserAnswer(): Register successful: ClientID 543055371, ClientIC 0`

## 3) Hunter received an incoming TeamViewer remote-control session from partner PSUT1 / ID 547298337

The strongest artifact is TeamViewer's own incoming-connections register, corroborated by the main TeamViewer log.

Key evidence:
- Source path / inode: `Program Files (x86)/TeamViewer/Connections_incoming.txt` inode `1418-128-1`
- Extract: `work/extracted/memory/teamviewer_connections_incoming.txt`
- SHA-256: `345ec858b644ae6b4807e5a42b6ce0878de3689a16840a7851f6790fe4d3778c`
- Command: `icat -o 0 inputs/4orensics.001 1418 > work/extracted/memory/teamviewer_connections_incoming.txt`

Quoted row:
- `547298337	PSUT1	21-06-2016 12:05:30	21-06-2016 12:14:29	Hunter	RemoteControl	{DFB7FCA2-0F07-4468-BE01-67D73CD83B3A}`

This row identifies:
- remote partner TeamViewer ID: `547298337`
- remote partner display name: `PSUT1`
- session owner on the local box: `Hunter`
- session type: `RemoteControl`
- start/end: `2016-06-21 12:05:30` to `2016-06-21 12:14:29` (UTC, matching TeamViewer router-clock evidence)

Corroborating log lines from `Program Files (x86)/TeamViewer/TeamViewer11_Logfile.log`:
- `2016/06/21 05:05:31.379 ... Connection incoming, sessionID = 456742019`
- `2016/06/21 05:05:32.091 ... Negotiating session encryption: client hello received from 547298337, RSA key length = 2048`
- `2016/06/21 05:05:59.784 ... CLoginServer::PasswordLogin: AuthOk with SRP(DynamicPassword)`
- `2016/06/21 05:05:59.832 ... participant PSUT1 (ID [547298337,1947434567]) was added`
- `2016/06/21 05:14:29.054 ... SessionEnded: 0`

Interpretation: Hunter's workstation accepted an authenticated incoming TeamViewer session from `PSUT1` / `547298337`.

## 4) That session exposed remote-control, file-transfer, clipboard, chat, and VPN capabilities

The TeamViewer log records both the stream types created during the session and the access-control settings applied.

Evidence:
- `work/extracted/memory/teamviewer_session_excerpt.txt` SHA-256 `67dd3a378dddb90def42dea49301aebcf81d63eb5a675ad1ee768ad47a427571`
- Same source inode `88429-128-4`

Quoted lines:
- `ReadStreamParameters(): streamID=10 type=24 (StreamType_Clipboard), source=[547298337,1947434567]`
- `ReadStreamParameters(): streamID=12 type=6 (StreamType_File), source=[547298337,1947434567]`
- `ConnectionAccessControl => RCAccessControl: RemoteControl='Allowed', FileTransfer='Allowed', ControlRemoteTV='Allowed', SwitchSides='Allowed', AllowDisableRemoteInput='Allowed', AllowVPN='Allowed', AllowPartnerViewDesktop='Allowed', ShareMyFiles='Allowed', ShareFilesWithMe='Allowed', PrintOnMyPrinters='Allowed', PrintOnRemotePrinters='Allowed'`

This proves the session was not just installed software sitting idle: the live TeamViewer session permitted remote control and multiple data-transfer channels.

## 5) TeamViewer hooks/shared-memory components touched user applications during the live session

While the remote session was active, TeamViewer logged shared-memory connections into multiple user processes, including browser, file-sync, and communications applications.

Evidence:
- Process excerpt: `work/extracted/memory/teamviewer_process_excerpt.txt`
- SHA-256: `635368fbbf0177ffeed609fd4fa9767b752b3bcf78cc229df9d4b214730b9e52`
- Source: `Program Files (x86)/TeamViewer/TeamViewer11_Logfile.log` inode `88429-128-4`

Quoted lines:
- `2016/06/21 05:06:00.236 ... explorer.exe: SharedMem Connected`
- `2016/06/21 05:06:00.238 ... googledrivesync.exe: SharedMem Connected`
- `2016/06/21 05:06:00.791 ... chrome.exe: SharedMem Connected`
- `2016/06/21 05:06:00.870 ... skype.exe: SharedMem Connected`
- `2016/06/21 05:06:02.279 ... ccleaner64.exe: SharedMem Connected`
- `2016/06/21 05:06:02.280 ... firefox.exe: SharedMem Connected`
- `2016/06/21 05:06:02.307 ... dropbox.exe: SharedMem Connected`
- `2016/06/21 05:08:14.478 ... zenmap.exe: SharedMem Connected`

Interpretation: during the incoming remote-control session, TeamViewer's desktop/hook components interacted with several active applications, including `chrome.exe`, `skype.exe`, `dropbox.exe`, and `googledrivesync.exe`. This is probative of live remote access to the user's desktop and applications.

## 6) Analyst conclusion for the report

Even without a RAM image, the disk artifacts are enough to support a strong conclusion:

- TeamViewer was installed for Hunter.
- TeamViewer registered local host ID `543055371`.
- An incoming TeamViewer `RemoteControl` session from partner `PSUT1` / `547298337` reached Hunter's workstation on `2016-06-21` from `12:05:30` to `12:14:29` UTC.
- During that session, TeamViewer allowed remote control, clipboard, file transfer, chat, and VPN, and attached to active user processes such as Chrome, Skype, Dropbox, Google Drive Sync, Firefox, and Zenmap.

This evidence is highly relevant to the policy-violation hypothesis and should be cross-correlated with browser, Skype, USB, LNK, event-log, and timeline artifacts from other seats.

## Ledger references

Recorded by this seat:
- remote partner IOC `547298337` / `PSUT1`
- TeamViewer session start event `2016-06-21T12:05:30Z`
- TeamViewer session end event `2016-06-21T12:14:29Z`
- finding that the session allowed remote control plus data-transfer channels

See `ledger/ledger.md`.
