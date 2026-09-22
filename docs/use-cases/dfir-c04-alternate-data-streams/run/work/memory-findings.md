# Memory forensics / execution-trace support

Agent: `sbe1802`

## Scope status

The assigned seat expected a memory image, but the evidence package and kickoff catalog do not contain one.

### Evidence

| Finding | Evidence |
| --- | --- |
| No memory image was provided in `inputs/` | `inputs` output lists only `inputs/StealthyADS.E01`, its CSV export, its acquisition text, and `inputs/CASE.md` (sha256 prefixes `52ffe320cf12`, `707f6f59ddec`, `a9156ec0430b`, `42da40f871bf`). |
| Kickoff catalog recorded zero memory images | `SWARM.md`, section `Evidence catalog`: `Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)`. |
| No obvious memory-adjacent system files were found in the catalogued file list | `grep -Ei '(^|/)(pagefile\.sys|hiberfil\.sys|swapfile\.sys|memory\.dmp|.*\.dmp)$' catalog/StealthyADS.E01/p0/filelist.txt` returned no matches. |

## Consequence

Volatility-based analysis, process memory inspection, injected-code review, and shellcode recovery cannot be performed from the provided evidence set. This seat will instead support the report by documenting the absence of memory evidence and by correlating execution traces from disk artifacts.

## Execution-trace support findings from ADS artifacts

### 1) Two desktop ADS payloads both contain the same PuTTY executable

| Host path | ADS name | Inode / attribute | Size | SHA-256 | Evidence of content |
| --- | --- | --- | ---: | --- | --- |
| `Users/IEUser/Desktop/creepy/welcome.txt` | `putty.exe` | `27771-128-5` | 809,984 B | `5bf9bc242130a3d1cce7112167e51b5d356d9771093a26fb774dbcbe2bb90994` | `icat -o 0 inputs/StealthyADS.E01 27771-128-5 | xxd -l 64 -g 1` shows `MZ`; `icat -o 0 inputs/StealthyADS.E01 27771-128-5 | strings | grep -Eim5 'PuTTY|Simon Tatham|putty'` returns `PuTTY` strings. |
| `Users/IEUser/Desktop/creepy/LPT1.txt` | `putty.exe` | `27953-128-4` | 809,984 B | `5bf9bc242130a3d1cce7112167e51b5d356d9771093a26fb774dbcbe2bb90994` | `icat -o 0 inputs/StealthyADS.E01 27953-128-4 | xxd -l 64 -g 1` shows `MZ`; the hash matches the `welcome.txt:putty.exe` stream exactly. |

Both streams are catalogued in `catalog/StealthyADS.E01/p0/filelist.txt` as:

- `Users/IEUser/Desktop/creepy/welcome.txt:putty.exe`
- `Users/IEUser/Desktop/creepy/LPT1.txt:putty.exe`

The parent directory for both is `Users/IEUser/Desktop/creepy` (MFT entry `59649-144-6`).

### 2) The stealthy execution case includes prefetch hidden inside ADS under `Windows/Prefetch`

| Host path | ADS name | Inode / attribute | Size | SHA-256 | Key timestamps from `istat` | Parsed prefetch result |
| --- | --- | --- | ---: | --- | --- | --- |
| `Windows/Prefetch/WELCOME.TXT` | `PUTTY.EXE-A6BB0639.pf` | `61166-128-4` | 6,462 B | `03a1a3c4c414fc68f58ca67025966280eaee5083e4022b80b459955494c22b06` | Created `2019-05-26 11:41:41.163407000 (+03)`; MFT modified `2019-05-26 11:49:33.081752000 (+03)` | `prefetch_mam` reports version `30`, compressed `true`, `exe_name: WELCOME.TXT:PUTTY.EXE`, `last_runs: [2019-05-26T08:41:32.929250Z]` |
| `Windows/Prefetch/WELCOME2.TXT` | `REVSHELL.EXE-41B5A636.pf` | `61167-128-4` | 2,703 B | `1661d820b23f4a7f4efc943cadbdddd4ef6f86f16b3b1a344678bb801ed7dbd8` | Created `2019-05-26 11:41:57.272890100 (+03)`; MFT modified `2019-05-26 11:49:33.081752000 (+03)` | `prefetch_mam` reports version `30`, compressed `true`, `exe_name: WELCOME2.TXT:REVSHELL.EXE`, `last_runs: [2019-05-26T08:41:52.069536Z]` |

These file-list entries directly show the stealth technique described in the case brief: instead of visible prefetch files such as `PUTTY.EXE-*.pf`, the artifacts were stored as ADS attached to seemingly harmless host files inside `Windows/Prefetch`.

More importantly, parsing the hidden `.pf` ADS proves the executed image names preserved the ADS syntax itself: `WELCOME.TXT:PUTTY.EXE` and `WELCOME2.TXT:REVSHELL.EXE`.

### 3) Timeline-relevant observations

- `welcome.txt` with ADS `putty.exe` was created at `2019-05-26 11:30:54.987311600 (+03)` (`2019-05-26T08:30:54.987312Z`).
- `LPT1.txt` with ADS `putty.exe` was created at `2019-05-26 11:36:19.382459900 (+03)` (`2019-05-26T08:36:19.382460Z`).
- Hidden prefetch ADS `WELCOME.TXT:PUTTY.EXE-A6BB0639.pf` was created at `2019-05-26 11:41:41.163407000 (+03)` (`2019-05-26T08:41:41.163407Z`).
- Hidden prefetch parsing reports the last run of `WELCOME.TXT:PUTTY.EXE` at `2019-05-26T08:41:32.929250Z`.
- Hidden prefetch ADS `WELCOME2.TXT:REVSHELL.EXE-41B5A636.pf` was created at `2019-05-26 11:41:57.272890100 (+03)` (`2019-05-26T08:41:57.272890Z`).
- Hidden prefetch parsing reports the last run of `WELCOME2.TXT:REVSHELL.EXE` at `2019-05-26T08:41:52.069536Z`.

These events and findings were also recorded into `ledger/ledger.md` for the timeline seat.

## Cross-source corroboration from Defender

`evtx_query` against `work/extracted/evtx/Defender-Operational.evtx` shows that Windows Defender later scanned `C:\Users\IEUser\Desktop` and detected `Trojan:Win32/Meterpreter.O` in:

- `C:\Users\IEUser\Desktop\creepy\COM1.txt:revshell.exe`
- `C:\Users\IEUser\Desktop\creepy\rev.exe`
- `C:\Users\IEUser\Desktop\creepy\welcome2.txt:revshell.exe`

Evidence command:

```bash
evtx_query {"path":"work/extracted/evtx/Defender-Operational.evtx","event_ids":[1000,1116,1117],"limit":10}
```

Relevant timestamps:

- scan started: `2019-05-26 08:43:09.842821+00:00` (event `1000`, record `39`)
- detection: `2019-05-26 08:43:13.957544+00:00` (event `1116`, record `40`)
- remediation succeeded: `2019-05-26 08:44:15.194506+00:00` (event `1117`, record `42`)

This corroborates that the hidden prefetch ADS `WELCOME2.TXT:REVSHELL.EXE-41B5A636.pf` corresponds to a revshell payload executed from ADS before Defender detected and remediated it.
