# Memory forensics findings (s9f2002)

## Scope and limitation

No standalone memory image was provided in `inputs/`, and the evidence catalog explicitly reports `0 memory image(s)` in `SWARM.md`.

Because of that, classic Volatility 3 live-memory analysis (process list, command lines, sockets, injected regions, DLL trees, shellcode) is **not possible from the supplied evidence**. I treated the disk-resident paging artifacts and Windows Error Reporting (WER) queue as the closest available substitutes.

## Available memory-like artifacts

### 1. `pagefile.sys`
- Active file: `pagefile.sys`
- Inode: `80986-128-1`
- Size in timeline: `1207959552` bytes
- Evidence:
  - `catalog/Windows8.1-Challenge3.001/p0/filelist.txt:117169`
  - `catalog/Windows8.1-Challenge3.001/p0/timeline.csv:373600`
  - `catalog/Windows8.1-Challenge3.001/p0/timeline.csv:396320`

### 2. `swapfile.sys`
- Active file: `swapfile.sys`
- Inode: `80988-128-1`
- Size in timeline: `268435456` bytes
- Evidence:
  - `catalog/Windows8.1-Challenge3.001/p0/filelist.txt:18369`
  - `catalog/Windows8.1-Challenge3.001/p0/timeline.csv:373604`
  - `catalog/Windows8.1-Challenge3.001/p0/timeline.csv:396321`

### 3. No hibernation or crash-memory artifacts found
I searched the catalog for `hiberfil.sys`, `MEMORY.DMP`, minidumps, and memory-image extensions. I found `pagefile.sys` and `swapfile.sys`, but no standalone memory dump.

Evidence:
- `catalog/Windows8.1-Challenge3.001/p0/filelist.txt`
- `catalog/Windows8.1-Challenge3.001/p0/bodyfile.txt`
- search command used:
  - `grep -inE 'hiberfil|pagefile|swapfile|memory\.dmp|\.dmp|\.mdmp|\.hdmp|\.(raw|mem|vmem)' catalog/Windows8.1-Challenge3.001/p0/filelist.txt`

## Windows Error Reporting (WER) observations

The WER queue under `ProgramData/Microsoft/Windows/WER/ReportQueue/` contains system reports created on `2015-12-12`.

### Windows Defender telemetry
- WER file inode: `84795-128-4`
- Path: `ProgramData/Microsoft/Windows/WER/ReportQueue/NonCritical_2152759308_19a56fc295d9f94116fa36d31393c2858a9cf4a6_00000000_cab_04d194f7/Report.wer`
- EventType: `MpTelemetry`
- EventTime decoded from WER: `2015-12-11T17:32:07.991226Z`
- AppPath: `C:\Program Files\Windows Defender\MsMpEng.exe`
- Evidence:
  - `catalog/Windows8.1-Challenge3.001/p0/filelist.txt:416`
  - extracted with `icat inputs/Windows8.1-Challenge3.001 84795`

### VirtualBox-related Plug and Play reports
Several WER queue entries at about `2015-12-12T03:03:15Z` describe device setup for VirtualBox hardware IDs:
- `USB\VID_80EE&PID_0021&REV_0100`
- `PCI\VEN_80EE&DEV_BEEF&SUBSYS_00000000&REV_00`
- `PCI\VEN_80EE&DEV_CAFE&SUBSYS_00000000&REV_00`

Relevant WER files:
- inode `81469-128-4` (`PnPGenericDriverFound`, USB input device)
- inode `81278-128-4` (`PnPGenericDriverFound`, Microsoft Basic Display Adapter, `VEN_80EE&DEV_BEEF`)
- inode `81287-128-4` (`PnPDriverNotFound`, `VEN_80EE&DEV_CAFE`)
- inode `81282-128-4` (`PnPRequestAdditionalSoftware`, `input.inf`)

Timeline evidence for the queued reports:
- `catalog/Windows8.1-Challenge3.001/p0/timeline.csv:392304`
- `catalog/Windows8.1-Challenge3.001/p0/timeline.csv:392311`

Interpretation: these artifacts are high-confidence evidence that the imaged Windows 8.1 system was running under VirtualBox around that time. They are environment/context artifacts, not intrusion proof by themselves.

## Pagefile string triage

I generated a strings pass from `pagefile.sys` into scratch (`work/s9f2002/pagefile.strings.txt`) and searched it for process, URL, and malware-related terms.

Commands used:
- `icat inputs/Windows8.1-Challenge3.001 80986 | strings -a -n 6 > work/s9f2002/pagefile.strings.txt`
- targeted greps over `work/s9f2002/pagefile.strings.txt`

### Low-confidence transient leads from pagefile
The pagefile contains numerous suspicious internet and malware-related strings, including examples such as:
- `http://update.winsrv64.com/setup/winsrv`
- `http://update.rundownplay.com/setup/rundownplay_setup_`
- `http://dl.dropbox.com/u/`
- `http://www.search4top.net/ie.asp`
- `http://www.searchcolours.com/install_.php?id=`

It also contains transient path fragments such as:
- `C:\Documents and Settings\Administrator\Application Data\Microsoft\Windows\System\`
- `C:\ProgramData\Media\`
- `\WinDefender 2009.lnk`

However, I did **not** find corroborating on-disk paths for those exact strings in the catalog at this stage. Without corroboration from disk, registry, prefetch, or event logs, I treat these pagefile-only hits as **leads, not conclusions**.

## Targeted corroboration against confirmed intrusion artifacts

After other seats confirmed the main intrusion artifacts, I re-queried `pagefile.strings.txt` for the following exact or partial indicators:
- `C:\Tools\README.txt`
- `C:\Users\master\Desktop\Docs\README.txt`
- `C:\Users\master\Desktop\Docs\Info.txt`
- `Hello master, Catch me if you can! Best regards, Your Admin ;)`
- `Your admin says hi to you ;)`
- `Nothing really interesting, just practicing some type writing :)`
- `Magnify.exe`
- `Utilman.exe`
- `sethc.exe`
- `net user master`
- `net localgroup administrators`

Result: I found **no reliable pagefile-string hit** for the taunt file contents, their full paths, or a usable attacker command line tied to those confirmed artifacts. `swapfile.sys` also yielded zero printable strings in a basic `strings -a -n 6` pass.

Interpretation: the supplied paging artifacts do not materially strengthen the confirmed intrusion narrative beyond what disk, registry, event-log, and prefetch evidence already prove.

## Current bottom line

1. No standalone memory capture exists in the supplied evidence, so Volatility-based live-memory findings cannot be produced honestly.
2. The strongest memory-adjacent artifacts available are `pagefile.sys`, `swapfile.sys`, and WER queue files.
3. WER shows the guest was operating in a VirtualBox environment around `2015-12-12T03:03:15Z`.
4. The pagefile holds potentially relevant malicious/transient strings, but they need corroboration from other seats before they can be claimed as evidence of the intrusion.

## Needs from other seats

If other seats identify a specific executable name, service name, URL, account, task, or path, I can pivot back into `pagefile.sys` and check whether memory-resident remnants of that artifact survive there.
