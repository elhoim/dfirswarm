# Installed software and provenance — seat s2f6605

Seat: Installed software and provenance — Uninstall keys, Program Files, installers on
disk, service and driver installs, who installed what and when.

Image: `inputs/BSidesAmman21.E01` — single NTFS volume, no partition table
(`icat -o 0 inputs/BSidesAmman21.E01 <inode>`). All timestamps below are UTC unless stated.

## 1. OS identity and install date

| Item | Value | Source / command |
| --- | --- | --- |
| ProductName | Windows 10 Enterprise Evaluation | `regipy` SOFTWARE hive `\Microsoft\Windows NT\CurrentVersion` |
| Build / release | 17134.1 (1803, rs4_release.180410-1804) | BuildLab / CurrentBuild / UBR=1 |
| InstallDate | 2018-04-25 20:00:46 UTC | `InstallDate = 1524686446` (epoch); `InstallTime = 131691600468526121` (FILETIME) — both decode to 2018-04-25 20:00:46.852 UTC |
| Computer name | MSEDGEWIN10 | SYSTEM `\ControlSet001\Control\ComputerName\ComputerName` |
| Time zone | Pacific Standard Time (Bias 480 = UTC-8) | SYSTEM `\ControlSet001\Control\TimeZoneInformation` (`ActiveTimeBias=480`) |

Command (quoted):
```
python3 - <<'PY'
from regipy.registry import RegistryHive
r = RegistryHive('work/s2f6605/registry/SOFTWARE')
k = r.get_key(r'\Microsoft\Windows NT\CurrentVersion')
for v in k.iter_values():
    if v.name in ('ProductName','CurrentBuild','BuildLabEx','InstallDate','InstallTime','ReleaseId'):
        print(v.name, '=', v.value)
PY
```
Output (excerpt):
```
ProductName = Windows 10 Enterprise Evaluation
CurrentBuild = 17134
BuildLabEx = 17134.1.amd64fre.rs4_release.180410-1804
InstallDate = 1524686446
InstallTime = 131691600468526121
ReleaseId = 1803
```

`InstallDate = 1524686446` = `2018-04-25 20:00:46 UTC`. This is the base image creation date;
the actual "activity of interest" is 2019-02-15.

## 2. Installed software (Uninstall keys)

Source: SOFTWARE hive `\Microsoft\Windows\CurrentVersion\Uninstall` (64-bit) and
`\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall` (32-bit).

| DisplayName | Version | InstallDate | InstallLocation / InstallSource | Publisher |
| --- | --- | --- | --- | --- |
| VMware Tools | 10.2.5.8068393 | 20190214 | `C:\Program Files\VMware\VMware Tools\` | VMware, Inc. |
| Puppet (64-bit) | 3.8.7 | 20180425 | `C:\Program Files\Puppet Labs\Puppet\` — InstallSource `C:\Users\IEUser\AppData\Local\Temp\chocolatey\puppet\3.8.7\` | Puppet Labs |
| Microsoft Silverlight | 5.1.50907.0 | 20180425 | `c:\Program Files\Microsoft Silverlight\` | Microsoft |
| Microsoft Visual C++ 2008 Redistributable - x64 | 9.0.30729.6161 | 20180425 | `c:\c0a7b417abb8defb8d\` | Microsoft |
| Microsoft Visual C++ 2008 Redistributable - x86 | 9.0.30729.6161 | 20180425 | (Wow6432Node) | Microsoft |
| OpenSSH for Windows 6.7p1-2 (remove only) | — | — | `"C:\Program Files\OpenSSH\uninstall.exe"` | Mark Saeger / Michael Johnson |

Key provenance point (quoted): the Puppet uninstall key's `InstallSource` is
`C:\Users\IEUser\AppData\Local\Temp\chocolatey\puppet\3.8.7\`. Chocolatey installs to the
invoking user's temp; this ties the Puppet install to **IEUser's** account and to
**Chocolatey** (`C:\ProgramData\chocolatey\` is present on disk).

## 3. Package manager / installers on disk

- `C:\ProgramData\chocolatey\` — Chocolatey package manager (choco.exe, chocolatey.exe,
  cinst/cuninst/cup/…, config\chocolatey.config). Body-file timestamps cluster at
  2018-04-25 (~1524686714–1524686795), i.e. the Puppet install day.
- `C:\Program Files\Puppet Labs\Puppet\` — Puppet Agent 3.8.7 tree (ruby.exe, facter, hiera).
- `C:\Program Files\OpenSSH\` — OpenSSH for Windows 6.7p1-2 (cygwin-based; bin/cygrunsrv.exe,
  ssh-keygen.exe, ssh-add.exe, etc.).
- `C:\Program Files\VMware\VMware Tools\` — VMware Tools 10.2.5.
- `C:\Users\IEUser\Downloads\SetMACE_v1009.zip` and
  `C:\Users\IEUser\Downloads\SetMACE_v1009\SetMACE_v1009\SetMace.exe` / `SetMace64.exe`
  (anti-forensics MAC-time tool) — used by IEUser; see UserAssist/BAM entries.

## 4. Services and drivers (non-Microsoft / relevant)

Source: SYSTEM hive `\ControlSet001\Services`.

| Service | Start | ImagePath | Notes |
| --- | --- | --- | --- |
| OpenSSHd | 2 (auto) | `C:\Program Files\OpenSSH\bin\cygrunsrv.exe` | "OpenSSH Server" |
| ssh-agent | 3 (demand) | `%SystemRoot%\System32\OpenSSH\ssh-agent.exe` | "OpenSSH Authentication Agent" |
| puppet | 2 (auto) | `"C:\Program Files\Puppet Labs\Puppet\sys\ruby\bin\ruby.exe" -rubygems "C:\Program Files\Puppet Labs\Puppet\...` | "Puppet Agent" |
| VMTools | 2 (auto) | `"C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"` | VMware Tools |
| VMware Physical Disk Helper Service | 2 (auto) | `...\vmacthlp.exe` | |
| VGAuthService | 2 (auto) | `...\VMware VGAuth\VGAuthService.exe` | |
| TPAutoConnSvc / TPVCGateway / VMwareCAF* | 3 | `...\VMware Tools\...` | VMware Tools helpers |
| bam | 1 | `system32\drivers\bam.sys` | Background Activity Moderator (driver) — used as execution evidence |

## 5. DCode.exe — the "tricky" question (Q12–Q15)

Summary answer, fully corroborated across seats (UserAssist, BAM, AmCache, Prefetch, file hash):

- **Q15 — location:** the DCode application is `C:\Users\Joker\DCode.exe` (inode `97020-128-5`,
  461952 bytes). It was executed under the **renamed filename** `C:\Users\Joker\dd.exe`
  (inode `97026-128-5`).
- **Q12 — user:** **Joker** (SID `S-1-5-21-597701057-294507186-493142324-1004`, RID 1004).
- **Q13 — times used:** **1**.
- **Q14 — last used:** `2019-02-15T05:02:12.791Z` (UserAssist) / `05:02:13.353878Z`
  (Prefetch) / `05:02:17.713Z` (BAM).

Evidence (each independent):

1. **Byte-identity.** `DCode.exe` and `dd.exe` have the same size and hash.
   ```
   shasum -a 256 work/s2f6605/extracted/DCode.exe work/s2f6605/extracted/dd.exe
   02b59b7ff4a5cd7a80f2c9c7d743af12850847c5a7448857e1a354490a8250b9  .../DCode.exe
   02b59b7ff4a5cd7a80f2c9c7d743af12850847c5a7448857e1a354490a8250b9  .../dd.exe
   cmp .../DCode.exe .../dd.exe   # IDENTICAL
   ```
2. **AmCache** (`Windows\appcompat\Programs\Amcache.hve`, inode `87786-128-3`), key
   `\Root\InventoryApplicationFile\dd.exe|8bbdf4af3d1b2e53`:
   ```
   LowerCaseLongPath = c:\users\joker\dd.exe
   Name = dd.exe
   Publisher = digital detective group ltd
   Version = 4.02.9306
   BinFileVersion = 4.2.0.9306
   ProductName = dcode
   LinkDate = 11/02/2009 14:15:58
   Size = 461952
   ```
   No `DCode.exe` entry exists in AmCache — only `dd.exe`.
3. **UserAssist** (Joker `NTUSER.DAT`): `C:\Users\Joker\dd.exe` `run_counter=1`,
   `focus_count=1`, `last_exec=2019-02-15T05:02:12.791Z`.
4. **BAM** (SYSTEM `\ControlSet001\Services\bam\UserSettings\S-1-5-21-...-1004`):
   `\Device\HarddiskVolume3\Users\Joker\dd.exe`, FILETIME `0x01d4c4eb9fc063e9`
   = `2019-02-15T05:02:17.713Z`.
5. **Prefetch** `Windows\Prefetch\DD.EXE-0C303FDD.pf` (inode `96361-128-4`) — decompressed by
   peer tool `mam_pf_parse`: `run_count=1`, `last_run_times_utc=["2019-02-15T05:02:13.353878Z"]`,
   executable `DD.EXE`. There is **no** `DCODE.EXE-*.pf`.

MAC times (from `istat`, UTC; `+03` shown by istat is the analysis host's display TZ, the NTFS
time zone on the box is Pacific):

| File | Created | Modified | MFT Modified | Accessed (SI) |
| --- | --- | --- | --- | --- |
| `C:\Users\Joker\DCode.exe` | 2019-02-15 04:59:22.463 | 04:59:23.104 | 04:59:23.104 | 05:01:40.276 |
| `C:\Users\Joker\dd.exe` | 2019-02-15 04:59:52.994 | 04:59:53.573 | 04:59:53.573 | 05:02:13.557 |

Owner of both files: Security ID `S-1-5-21-597701057-294507186-493142324-1004` = **Joker**
(SAM RID `000003EC` = 1004; SAM `Names\Joker`).

**Conclusion:** DCode was placed in Joker's profile, renamed to `dd.exe`, and run **once** by
Joker on 2019-02-15 ~05:02:12–05:02:17 UTC. The "tricky" part is that a naive search for
`DCode.exe` execution (prefetch/UserAssist/AmCache) comes up empty because the binary was
executed under the name `dd.exe`.

## 6. Other provenance notes (context for the case)

- Accounts in SAM: `IEUser` (RID 1000, created 2018-04-25), `Joker` (RID 1004, password set
  2019-02-15 04:53:33 UTC, 4 logons, last login 05:33:51 UTC), `sshd` (RID 1002, disabled),
  `sshd_server` (RID 1003). Joker is the second, later-added account; IEUser is the original
  MS Edge VM account (computer `MSEDGEWIN10`, VM password `Passw0rd!` per README.rtf).
- `IEUser`'s profile shows anti-forensics tooling: `SetMace.exe`/`SetMace64.exe` (MAC-time
  editor), `sync64.exe` (Sysinternals Sync — flushes dirty data), `putty.exe`. Joker's profile
  shows `dd.exe` (DCode), `putty.exe`, `dd`/`haha.png`/`Confidential.rtf`.
