# Installed software and provenance (s9f2005)

Scope: Uninstall keys, Program Files, installers on disk, service and driver
installs, and "who installed what and when" on `inputs/Windows8.1-Challenge3.001`
(single NTFS volume, no partition table; inodes referenced with `icat -o 0`).

## Executive summary

This is a **stock Windows 8.1 Enterprise (build 9600, amd64) VirtualBox guest**.
The only third-party program ever installed is **Oracle VM VirtualBox Guest
Additions 5.0.10**. There is **no** evidence of any attacker-installed software,
service, or driver: every uninstall entry, service, and driver resolves to a
stock Windows component or a VirtualBox Guest Additions component. The intrusion
left no persistence in the software/provenance layer (no new programs, no
malicious service/driver). The provenance layer instead pins down the *who/when*
of the system: the victim account `master`, the built-in `Administrator`, and
the tool sequence the attacker actually ran (via Prefetch).

## Installed programs (Uninstall keys)

Source: `\Microsoft\Windows\CurrentVersion\Uninstall` and
`\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` in the SOFTWARE hive
(icat inode **45568** → `work/extracted/hives/SOFTWARE`). Dump:
`work/s9f2005/uninstall.json` (27 entries).

| Program | Version | Publisher | Notes |
| --- | --- | --- | --- |
| Oracle VM VirtualBox Guest Additions | 5.0.10.0 | Oracle Corporation | Only third-party program. UninstallString `C:\Program Files\Oracle\VirtualBox Guest Additions\uninst.exe` |
| AddressBook, Connection Manager, DirectDrawEx, DXM_Runtime, Fontcore, IE40, IE4Data, IE5BAKEX, IEData, MobileOptionPack, MPlayer2, SchedulingAgent, WIC (x2, 32/64-bit) | — | — | Stock Windows component stubs (no DisplayName/version); present in both Uninstall and WOW6432Node Uninstall |

Program Files / Program Files (x86) top-level directories confirm the same
conclusion: only `Oracle\VirtualBox Guest Additions` is non-Microsoft
(`filelist.txt`).

## Installers on disk

No third-party installers were found. `Program Files/Uninstall Information` is
empty. The only `.exe/.msi` installer-like files on the volume are Windows
components (`setup_wm.exe`, `msiexec.exe`, `setup.exe` in WinSxS/Panther, etc.).
See `filelist.txt` grep for `(setup|install).*\.(exe|msi|msu)`.

## Services and drivers (SYSTEM hive)

Source: `\ControlSet001\Services` in the SYSTEM hive (icat inode **44233** →
`work/extracted/hives/SYSTEM`). `\Select` = Current 1. Dump:
`work/s9f2005/services_cs1.json`.

- **469 services**, **254 of them drivers** (Type 1/2).
- Every service/driver ImagePath resolves to `%SystemRoot%\system32`/`syswow64`
  or to a stock Microsoft location; the only non-system32 services are
  `NetTcpPortSharing`, `TrustedInstaller`, `WdNisSvc`, `WinDefend`,
  `WMPNetworkSvc` (all stock).
- VirtualBox drivers present: `VBoxGuest`, `VBoxMouse`, `VBoxSF`,
  `VBoxVideoW8` (Guest Additions 5.0.10) — normal for this VM.
- **No suspicious service or driver** (nothing under Temp/Users/Program Files,
  no random-named drivers, no ImagePath pointing at attacker content).

## Provenance / "who installed what and when"

### System and accounts

| Fact | Value | Evidence |
| --- | --- | --- |
| OS | Windows 8.1 Enterprise 6.3.9600 (amd64), EditionID Enterprise | SOFTWARE `\Microsoft\Windows NT\CurrentVersion` |
| RegisteredOwner | `master` | SOFTWARE `\Microsoft\Windows NT\CurrentVersion` |
| InstallDate (registry) | 2015-12-12T03:03:15Z (epoch 1449889395) | SOFTWARE `...\CurrentVersion\InstallDate` |
| User profiles | `C:\Users\master` (SID ...-1001), `C:\Users\Administrator` (SID ...-500) | SOFTWARE `\Microsoft\Windows NT\CurrentVersion\ProfileList` |
| VirtualBox GA install | uninstall key last_modified 2015-12-12T03:28:24Z | SOFTWARE `...\Uninstall\Oracle VM VirtualBox Guest Additions` NK last_modified FILETIME 130943645046486404 |
| `master` account created | 2015-12-12T03:02:42Z (SAM PasswordLastSet == creation time; Security EID 4720 rec 126, SYSTEM context) | SAM `\SAM\Domains\Account\Users\000003E9` F value + Security.evtx 4720 (s9f2001) |
| `master` profile materialized | 2015-12-12T03:03:16–03:03:19Z | `/Users/master` dir inode **81298** (birth 03:03:16Z) + `NTUSER.DAT` inode **81309** (created 03:03:19Z) |
| `master` SAM record last modified | 2015-12-11T17:30:45Z (post-rollback raw stamp) | SAM key last_modified |
| `Administrator` last logon | 2015-12-12T03:25:14Z | SAM `\SAM\Domains\Account\Users\000001F4` F value LastLogon |
| `Administrator` password last set | 2014-03-18T10:20:39Z (never changed since install media) | SAM `...\000001F4` F value |
| `master` password hint | `What is this?` | SAM `...\000003E9` UserPasswordHint (UTF-16LE) |
| PASSWD.LOG | **empty (0 bytes)** — no password change was logged via the Change-Password path | `Windows/debug/PASSWD.LOG` inode **81005** (created 2015-12-12T02:18Z, modified 03:30Z) |

> Note on `InstallDate`: the registry InstallDate (2015-12-12T03:03:15Z) is
> consistent with the forward-clock phase (account creation 03:02:42Z, first
> master logon 03:03:16Z). The apparent anomaly — a `master` SAM record and
> Prefetch burst stamped `2015-12-11T17:30Z` *before* InstallDate — is explained
> by s9f2001's clock-rollback finding: `VBoxService.exe` rolled the guest clock
> from `2015-12-12T03:30:35Z` back to `2015-12-11T17:30:37Z` (Security EID 4616
> rec 333 / System EID 1 rec 266), so any file timestamps after that rollback
> point carry `2015-12-11T17:30Z+` values that are actually *later* in real
> sequence than the `2015-12-12T03:30:35Z` rollback point. Do not read raw
> timestamps in chronological order across that boundary.

> `master` origin: the ProfileList entry (SID ...-1001) has no pre-2015
> timestamp (`last_modified` 2015-12-12T03:30:12Z); the profile directory and
> NTUSER.DAT were both created 03:03:16–03:03:19Z, right after the 4720
> (03:02:42Z) and InstallDate (03:03:15Z). Files inside `C:\Users\master` that
> carry `2013-06-18` timestamps are `m...` (modified-only) default-profile
> template copies (AppData\Local\Packages\*.settingcontent-ms), not evidence of
> a pre-existing interactive profile. This is the fresh-install/OOBE pattern.
> Open question (mechanism, not timing): whether that 4720 was OOBE-driven vs.
> backdoor-driven `net user master` — `SubjectUserSid=SYSTEM` alone does not
> distinguish the two.

### Attacker tool sequence (Prefetch) — provenance of *what ran*

Prefetch files record first run of executables. Relevant markers
(`catalog/.../timeline.csv`, UTC):

| Tool | First seen (UTC) | Re-run in attack window (UTC) | Purpose |
| --- | --- | --- | --- |
| TAKEOWN.EXE | 2015-12-11T17:31:19Z | 2015-12-12T03:28:23Z | take ownership of files (prep for Magnify/Utilman swap) |
| UTILMAN.EXE | 2015-12-11T17:31:19Z | 2015-12-12T03:26:03Z | Utility Manager (2nd accessibility backdoor target) |
| MAGNIFY.EXE | 2015-12-11T17:31:19Z | 2015-12-12T03:26:13Z | Magnifier (accessibility backdoor target) |
| NET.EXE / NET1.EXE | 2015-12-11T17:31:19Z | 2015-12-12T03:26:19Z | `net user` / account management |
| SC.EXE | 2015-12-11T17:31:19Z | 2015-12-12T03:27:51Z | service control |

The 2015-12-12T03:26–03:28Z re-runs line up with the confirmed
Magnify→cmd.exe swap and the `master` password reset (03:02:42Z) / built-in
`Administrator` logon (03:25:14Z). This ties the *provenance* layer to the
intrusion: the attacker used `takeown` to seize the accessibility binaries,
then `net`/`sc` for account and service actions.

## Files produced

- `work/extracted/hives/SOFTWARE` (icat inode 45568, MD5 c3ec5a8a57eb1c4a3d621846a89a6c18)
- `work/extracted/hives/SYSTEM` (icat inode 44233, MD5 9848de1c29a52eebcdbb090f785478a8)
- `work/extracted/hives/SAM` (icat inode 44227, MD5 e754a1c23257f836ee3a3416ae8ca9b8)
- `work/s9f2005/uninstall.json`, `work/s9f2005/services_cs1.json`

## Open questions for other seats

- s9f2001: ✅ answered — `master` was *created* at 03:02:42Z (Security EID 4720,
  SYSTEM context) then added to Users/Administrators (4732), not a password
  reset of a pre-existing account; the SAM PasswordLastSet == creation time.
  Remaining: confirm whether the Administrator enable/disable (4722/4738) at
  03:21:08Z/03:26:19Z maps to specific commands.
- s9f2000/s9f2004: InstallDate ordering is now explained by the VBoxService
  clock rollback (EID 4616); incorporate that into the timeline narrative.
- s9f2003: `C:\Users\master\AppData\Local\Temp\ad_driver.sys` (inode 81252) —
  is it the "driver" the SC/`ad_driver` activity refers to?
