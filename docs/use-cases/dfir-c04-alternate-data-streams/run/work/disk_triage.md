# Disk triage — sbe1800

## Scope

Assigned seat: filesystem/layout triage, attacker-added or attacker-changed paths in the attack window, and inode-backed evidence for suspicious files and alternate data streams (ADS).

## Filesystem layout

- Image: `inputs/StealthyADS.E01`
- Partitioning: no partition table; the E01 contains one NTFS volume starting at sector 0.
  - Evidence: `catalog/StealthyADS.E01/partitions.txt`
  - Output: `No partition table: inputs/StealthyADS.E01 is one NTFS volume starting at sector 0 (use the tools without -o).`
- Filesystem: NTFS volume named **Windows 10**.
  - Evidence: `catalog/StealthyADS.E01/p0/fsstat.txt`
  - Key fields: sector size 512, cluster size 4096, root directory inode 5, MFT entry size 1024.

## Working attack window from on-disk changes

The suspicious Desktop files, hidden Prefetch streams, and Defender activity cluster between **2019-05-26 08:30:31Z** and **2019-05-26 08:49:33Z**.

Start anchor:
- `2019-05-26T08:30:31Z` `/Users/IEUser/Desktop/creepy` (`59649-144-6`) created.

Middle anchors:
- `2019-05-26T08:41:32.929250Z` hidden Prefetch ADS `WELCOME.TXT:PUTTY.EXE-A6BB0639.pf` records a run for `WELCOME.TXT:PUTTY.EXE`.
- `2019-05-26T08:41:52.069536Z` hidden Prefetch ADS `WELCOME2.TXT:REVSHELL.EXE-41B5A636.pf` records a run for `WELCOME2.TXT:REVSHELL.EXE`.
- `2019-05-26T08:43:13.944Z` Defender detects `Trojan:Win32/Meterpreter.O` in `COM1.txt:revshell.exe`, `rev.exe`, and `welcome2.txt:revshell.exe`.
- `2019-05-26T08:44:15.194506Z` Defender remediates the same detection set.

End anchor:
- `2019-05-26T08:49:33Z` hidden Prefetch ADS under `/Windows/Prefetch/` (`61166-128-4`, `61167-128-4`) metadata changed in the catalog timeline.

## Non-system ADS inventory

I filtered `catalog/StealthyADS.E01/p0/filelist.txt` for paths containing `:` and excluded `Zone.Identifier`, `WofCompressedData`, and NTFS metadata streams. That left **four extant relevant ADS entries in the current catalog**.

I also checked the imager-exported UTF-16LE CSV `inputs/StealthyADS.E01.csv`; it enumerates ADS as nested path components such as `...\LPT1.txt\putty.exe` and `...\WELCOME.TXT\PUTTY.EXE-A6BB0639.pf`. Both the catalog file list and the CSV produced **zero `Zone.Identifier` hits**.

Important qualifier: Defender Operational events also show **additional malicious ADS that were no longer present in the extant file list by the time of acquisition/remediation**: `C:\Users\IEUser\Desktop\creepy\COM1.txt:revshell.exe` and `C:\Users\IEUser\Desktop\creepy\welcome2.txt:revshell.exe`. Those extra ADS are discussed below as log-corroborated prior states, not current file-list entries.

| Host path | Inode/attr | Stream name | Size | SHA-256 | What it contains | Evidence |
| --- | --- | --- | ---: | --- | --- | --- |
| `Users/IEUser/Desktop/creepy/welcome.txt` | `27771-128-5` | `putty.exe` | 809,984 | `5bf9bc242130a3d1cce7112167e51b5d356d9771093a26fb774dbcbe2bb90994` | PE executable; strings identify **PuTTY** | `fls -p inputs/StealthyADS.E01 59649`; `istat inputs/StealthyADS.E01 27771`; `icat inputs/StealthyADS.E01 27771-128-5 | xxd -l 64 -g 1`; `icat ... | strings | sed -n '1,40p'` |
| `Users/IEUser/Desktop/creepy/LPT1.txt` | `27953-128-4` | `putty.exe` | 809,984 | `5bf9bc242130a3d1cce7112167e51b5d356d9771093a26fb774dbcbe2bb90994` | PE executable; byte-identical to the other `putty.exe` stream and to on-disk `creepy/putty.exe` | `fls -p inputs/StealthyADS.E01 59649`; `istat inputs/StealthyADS.E01 27953`; `icat inputs/StealthyADS.E01 27953-128-4 | openssl dgst -sha256` |
| `Windows/Prefetch/WELCOME.TXT` | `61166-128-4` | `PUTTY.EXE-A6BB0639.pf` | 6,462 | `03a1a3c4c414fc68f58ca67025966280eaee5083e4022b80b459955494c22b06` | Hidden Prefetch file stored as ADS; header begins `MAM`, consistent with compressed Windows Prefetch data | `fls -p inputs/StealthyADS.E01 80816 | grep WELCOME`; `istat inputs/StealthyADS.E01 61166`; `icat inputs/StealthyADS.E01 61166-128-4 | xxd -l 64 -g 1` |
| `Windows/Prefetch/WELCOME2.TXT` | `61167-128-4` | `REVSHELL.EXE-41B5A636.pf` | 2,703 | `1661d820b23f4a7f4efc943cadbdddd4ef6f86f16b3b1a344678bb801ed7dbd8` | Hidden Prefetch file stored as ADS; name indicates a Prefetch artifact for `REVSHELL.EXE`; header begins `MAM` | `fls -p inputs/StealthyADS.E01 80816 | grep WELCOME`; `istat inputs/StealthyADS.E01 61167`; `icat inputs/StealthyADS.E01 61167-128-4 | xxd -l 64 -g 1` |

## Attacker-added or attacker-touched paths in the attack window

The following paths are the main suspicious additions/changes visible from the body file and MAC timeline.

| Time (UTC) | Path | Inode/attr | Notes | Evidence |
| --- | --- | --- | --- | --- |
| 2019-05-26 08:30:31 | `/Users/IEUser/Desktop/creepy` | `59649-144-6` | Suspicious working directory created | `timeline.csv`, `bodyfile.txt`, `istat 59649` |
| 2019-05-26 08:30:54 | `/Users/IEUser/Desktop/creepy/welcome.txt` | `27771-128-1` | Plain-text lure file created | `timeline.csv`, `bodyfile.txt`, `istat 27771` |
| 2019-05-26 08:30:54 | `/Users/IEUser/Desktop/creepy/welcome.txt:putty.exe` | `27771-128-5` | PuTTY hidden in ADS | `timeline.csv`, `bodyfile.txt`, `istat 27771` |
| 2019-05-26 08:31:53 | `/Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/welcome.txt.lnk` | `27782-128-4` | Recent-item shortcut pointing to `C:\Users\IEUser\Desktop\creepy\welcome.txt` | `timeline.csv`; `icat inputs/StealthyADS.E01 27782-128-4 | strings` |
| 2019-05-26 08:31:53 | `/Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/creepy.lnk` | `27839-128-1` | Recent-item shortcut pointing to `C:\Users\IEUser\Desktop\creepy` | `timeline.csv`; `icat inputs/StealthyADS.E01 27839-128-1 | strings` |
| 2019-05-26 08:32:47 | `/Users/IEUser/Desktop/creepy/putty.exe` | `61331-128-1` | Regular on-disk copy of PuTTY appears; same SHA-256 as both PuTTY ADS payloads | `timeline.csv`, `bodyfile.txt`, `istat 61331`, `icat ... | openssl dgst -sha256` |
| 2019-05-26 08:33:04 | `/Users/IEUser/Desktop/creepy/welcome2.txt` | `61378-128-1` | Second lure file created | `timeline.csv`, `bodyfile.txt` |
| 2019-05-26 08:36:19 | `/Users/IEUser/Desktop/creepy/LPT1.txt` | `27953-128-1` | Host file uses a device-like filename | `timeline.csv`, `bodyfile.txt`, `istat 27953` |
| 2019-05-26 08:36:19 | `/Users/IEUser/Desktop/creepy/LPT1.txt:putty.exe` | `27953-128-4` | PuTTY hidden in ADS on the device-like file | `timeline.csv`, `bodyfile.txt`, `istat 27953` |
| 2019-05-26 08:36:49 | `/Users/IEUser/Desktop/creepy/COM1.txt` | `61387-128-1` | Another device-like filename, likely part of the stealth test setup | `timeline.csv`, `bodyfile.txt` |
| 2019-05-26 08:40:21 | `/Users/IEUser/Desktop/creepy/master.txt` | `61138-128-1` | Text file created in the same staging directory | `timeline.csv`, `bodyfile.txt` |
| 2019-05-26 08:41:41 | `/Windows/Prefetch/WELCOME.TXT` | `61166-128-1` | Zero-byte host file for hidden Prefetch ADS | `timeline.csv`, `bodyfile.txt`, `istat 61166` |
| 2019-05-26 08:41:41 | `/Windows/Prefetch/WELCOME.TXT:PUTTY.EXE-A6BB0639.pf` | `61166-128-4` | Hidden Prefetch for `PUTTY.EXE` | `timeline.csv`, `bodyfile.txt`, `istat 61166` |
| 2019-05-26 08:41:57 | `/Windows/Prefetch/WELCOME2.TXT` | `61167-128-1` | Zero-byte host file for hidden Prefetch ADS | `timeline.csv`, `bodyfile.txt`, `istat 61167` |
| 2019-05-26 08:41:57 | `/Windows/Prefetch/WELCOME2.TXT:REVSHELL.EXE-41B5A636.pf` | `61167-128-4` | Hidden Prefetch for `REVSHELL.EXE` | `timeline.csv`, `bodyfile.txt`, `istat 61167` |
| 2019-05-26 08:43:13 | `C:\Users\IEUser\Desktop\creepy\COM1.txt:revshell.exe` | log-only | Defender detects a malicious ADS not preserved in the extant file list | `evtx_query` on Defender Operational record 40 |
| 2019-05-26 08:43:13 | `C:\Users\IEUser\Desktop\creepy\welcome2.txt:revshell.exe` | log-only | Defender detects a second malicious ADS not preserved in the extant file list | `evtx_query` on Defender Operational record 40 |
| 2019-05-26 08:43:13 | `C:\Users\IEUser\Desktop\creepy\rev.exe` | log-only | Defender also detects a standalone executable in the same directory | `evtx_query` on Defender Operational record 40 |

## Hidden Prefetch parse results

I extracted the two hidden Prefetch ADS into `work/sbe1800/` and parsed them with the forged tool `prefetch_mam`.

| Hidden Prefetch ADS | Tool result |
| --- | --- |
| `work/sbe1800/WELCOME.TXT_PUTTY.EXE-A6BB0639.pf.ads` | compressed `MAM`, Prefetch v30, `exe_name` = `WELCOME.TXT:PUTTY.EXE`, `last_runs` = `2019-05-26T08:41:32.929250Z` |
| `work/sbe1800/WELCOME2.TXT_REVSHELL.EXE-41B5A636.pf.ads` | compressed `MAM`, Prefetch v30, `exe_name` = `WELCOME2.TXT:REVSHELL.EXE`, `last_runs` = `2019-05-26T08:41:52.069536Z` |

This confirms the stealthy case is not just a hidden `.pf` filename: the ADS content is parseable Prefetch data for execution from ADS-style names.

## Host-file contents for the lure files

Small resident file contents extracted with `icat`:

- `27771-128-1` (`welcome.txt`):
  ```text
  hello dfir 
  find the stealthy ADS artifacts 
  good luck 
  ```
- `27953-128-1` (`LPT1.txt`):
  ```text
  Stealthy file 
  ```
- `61378-128-1` (`welcome2.txt`):
  ```text
  hello dfir 
  find the stealthy ADS artifacts 
  good luck 
  ```
- `61387-128-1` (`COM1.txt`):
  ```text
  Stealthy file2 
  ```
- `61138-128-1` (`master.txt`):
  ```text
  greetings from the master 
  ```

## Inode-backed proof of the ADS

### `welcome.txt:putty.exe`

`istat inputs/StealthyADS.E01 27771` shows:
- host file `welcome.txt`
- resident unnamed `$DATA (128-1)` size 59
- named `$DATA (128-5)` **Name: `putty.exe`** size 809984

### `LPT1.txt:putty.exe`

`istat inputs/StealthyADS.E01 27953` shows:
- host file `LPT1.txt`
- resident unnamed `$DATA (128-1)` size 16
- named `$DATA (128-4)` **Name: `putty.exe`** size 809984

### Hidden Prefetch ADS

`istat inputs/StealthyADS.E01 61166` shows:
- host file `WELCOME.TXT`
- unnamed `$DATA (128-1)` size 0
- named `$DATA (128-4)` **Name: `PUTTY.EXE-A6BB0639.pf`** size 6462

`istat inputs/StealthyADS.E01 61167` shows:
- host file `WELCOME2.TXT`
- unnamed `$DATA (128-1)` size 0
- named `$DATA (128-4)` **Name: `REVSHELL.EXE-41B5A636.pf`** size 2703

## Detection methods demonstrated on this image

### 1. Recursive file listing catches non-hidden ADS names

Command:
```bash
grep -n ':[^/[:space:]]' catalog/StealthyADS.E01/p0/filelist.txt
```

Relevant output lines:
```text
r/r 27953-128-4: Users/IEUser/Desktop/creepy/LPT1.txt:putty.exe
r/r 27771-128-5: Users/IEUser/Desktop/creepy/welcome.txt:putty.exe
r/r 61166-128-4: Windows/Prefetch/WELCOME.TXT:PUTTY.EXE-A6BB0639.pf
r/r 61167-128-4: Windows/Prefetch/WELCOME2.TXT:REVSHELL.EXE-41B5A636.pf
```

### 2. The imager-exported CSV also exposes ADS paths

Command pattern used:
```bash
python3 - <<'PY'
from pathlib import Path
text = Path('inputs/StealthyADS.E01.csv').read_text('utf-16le', errors='ignore')
for line_no, line in enumerate(text.splitlines(), 1):
    if any(t.lower() in line.lower() for t in ['LPT1.txt','welcome.txt','PUTTY.EXE-A6BB0639.pf','REVSHELL.EXE-41B5A636.pf']):
        print(f'{line_no}:{line}')
PY
```

Relevant output lines:
```text
24185:putty.exe    Windows 10 [NTFS]\[root]\Users\IEUser\Desktop\creepy\LPT1.txt\putty.exe    809984 ...
24186:putty.exe    Windows 10 [NTFS]\[root]\Users\IEUser\Desktop\creepy\welcome.txt\putty.exe    809984 ...
35822:PUTTY.EXE-A6BB0639.pf    Windows 10 [NTFS]\[root]\Windows\Prefetch\WELCOME.TXT\PUTTY.EXE-A6BB0639.pf    6462 ...
35823:REVSHELL.EXE-41B5A636.pf    Windows 10 [NTFS]\[root]\Windows\Prefetch\WELCOME2.TXT\REVSHELL.EXE-41B5A636.pf    2703 ...
```

A separate UTF-16LE scan of the CSV returned `Zone.Identifier count 0`.

### 3. `fls` on the parent directory reveals ADS that a normal Explorer-style listing would miss

Command:
```bash
fls -p inputs/StealthyADS.E01 59649
```

Relevant output:
```text
r/r 27953-128-1: LPT1.txt
r/r 27953-128-4: LPT1.txt:putty.exe
r/r 27771-128-1: welcome.txt
r/r 27771-128-5: welcome.txt:putty.exe
```

Command:
```bash
fls -p inputs/StealthyADS.E01 80816 | grep WELCOME
```

Relevant output:
```text
r/r 61166-128-1: WELCOME.TXT
r/r 61166-128-4: WELCOME.TXT:PUTTY.EXE-A6BB0639.pf
r/r 61167-128-1: WELCOME2.TXT
r/r 61167-128-4: WELCOME2.TXT:REVSHELL.EXE-41B5A636.pf
```

### 4. `istat` proves the named `$DATA` attributes at the inode level

Commands:
```bash
istat inputs/StealthyADS.E01 27771
istat inputs/StealthyADS.E01 27953
istat inputs/StealthyADS.E01 61166
istat inputs/StealthyADS.E01 61167
```

These show the named `$DATA` attributes (`putty.exe`, `PUTTY.EXE-A6BB0639.pf`, `REVSHELL.EXE-41B5A636.pf`) and their sizes.

### 5. `icat` confirms content type and lets the analyst hash the hidden data

Commands:
```bash
icat inputs/StealthyADS.E01 27771-128-5 | xxd -l 64 -g 1
icat inputs/StealthyADS.E01 27771-128-5 | strings | sed -n '1,40p'
icat inputs/StealthyADS.E01 61166-128-4 | xxd -l 64 -g 1
icat inputs/StealthyADS.E01 61167-128-4 | xxd -l 64 -g 1
```

Results:
- both `putty.exe` ADS payloads start with `MZ` and include `PuTTY` strings
- both hidden Prefetch ADS start with `MAM`, consistent with compressed Prefetch content
- `prefetch_mam` parses them as Prefetch v30 and reports run times for `WELCOME.TXT:PUTTY.EXE` and `WELCOME2.TXT:REVSHELL.EXE`
- `evtx_query` against Defender Operational confirms additional malicious ADS in the same directory (`COM1.txt:revshell.exe` and `welcome2.txt:revshell.exe`) that are not preserved in the extant file list

## Notes for other seats

- The hidden Prefetch ADS are strong execution evidence for `PUTTY.EXE` and `REVSHELL.EXE`, but Prefetch parsing/execution interpretation belongs with the leftovers / execution-analysis seats.
- Defender / AV review should focus on the same UTC window: `2019-05-26 08:30:31Z` through `2019-05-26 08:49:33Z`.
- All dated milestones and key IOCs from this note have been recorded into `ledger/ledger.md`.
