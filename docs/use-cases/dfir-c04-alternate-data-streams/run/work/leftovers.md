# Leftovers and malware findings (sbe1803)

This note covers the leftover artifacts around the ADS exercises: lure files, dropped tools, hidden Prefetch streams, Recent Items links, and Defender detections. It did **not** find evidence of an IIS/Apache/XAMPP web root or an attacker-created scheduled task/service; the malicious activity is concentrated in `C:\Users\IEUser\Desktop\creepy` and in hidden Prefetch ADS under `C:\Windows\Prefetch`.

Relevant timeline and findings are also recorded in `ledger/ledger.md` (events 55-64, 79; findings 69-70, 78; IOCs 65-68).

## 1. Suspicious user-space artifacts under `C:\Users\IEUser\Desktop\creepy`

Catalog file list:

```text
5345:d/d 59649-144-6:    Users/IEUser/Desktop/creepy
5346:r/r 61387-128-1:    Users/IEUser/Desktop/creepy/COM1.txt
5347:r/r 27953-128-1:    Users/IEUser/Desktop/creepy/LPT1.txt
5348:r/r 27953-128-4:    Users/IEUser/Desktop/creepy/LPT1.txt:putty.exe
5349:r/r 61138-128-1:    Users/IEUser/Desktop/creepy/master.txt
5350:r/r 61331-128-1:    Users/IEUser/Desktop/creepy/putty.exe
5351:r/r 27771-128-1:    Users/IEUser/Desktop/creepy/welcome.txt
5352:r/r 27771-128-5:    Users/IEUser/Desktop/creepy/welcome.txt:putty.exe
5353:r/r 61378-128-1:    Users/IEUser/Desktop/creepy/welcome2.txt
```

Source: `catalog/StealthyADS.E01/p0/filelist.txt`

Creation / access timeline excerpts:

```text
551482:2019-05-26T08:30:31Z ... /Users/IEUser/Desktop/creepy
553399:2019-05-26T08:30:54Z ... /Users/IEUser/Desktop/creepy/welcome.txt
553400:2019-05-26T08:30:54Z ... /Users/IEUser/Desktop/creepy/welcome.txt:putty.exe
555020:2019-05-26T08:32:47Z ... /Users/IEUser/Desktop/creepy/putty.exe
555030:2019-05-26T08:33:04Z ... /Users/IEUser/Desktop/creepy/welcome2.txt
555072:2019-05-26T08:36:19Z ... /Users/IEUser/Desktop/creepy/LPT1.txt
555073:2019-05-26T08:36:19Z ... /Users/IEUser/Desktop/creepy/LPT1.txt:putty.exe
555075:2019-05-26T08:36:49Z ... /Users/IEUser/Desktop/creepy/COM1.txt
555271:2019-05-26T08:43:11Z .a.. /Users/IEUser/Desktop/creepy/LPT1.txt
555272:2019-05-26T08:43:11Z .a.. /Users/IEUser/Desktop/creepy/LPT1.txt:putty.exe
555274:2019-05-26T08:43:12Z .a.. /Users/IEUser/Desktop/creepy/putty.exe
555275:2019-05-26T08:43:13Z .a.. /Users/IEUser/Desktop/creepy/welcome.txt
555276:2019-05-26T08:43:13Z .a.. /Users/IEUser/Desktop/creepy/welcome.txt:putty.exe
```

Source: `catalog/StealthyADS.E01/p0/timeline.csv`

Contents of the lure / marker files extracted with `icat -o 0 inputs/StealthyADS.E01 <inode>-128-1`:

| Path | Inode | Extracted text |
| --- | --- | --- |
| `C:\Users\IEUser\Desktop\creepy\welcome.txt` | `27771` | `hello dfir / find the stealthy ADS artifacts / good luck` |
| `C:\Users\IEUser\Desktop\creepy\welcome2.txt` | `61378` | same text as `welcome.txt` |
| `C:\Users\IEUser\Desktop\creepy\LPT1.txt` | `27953` | `Stealthy file` |
| `C:\Users\IEUser\Desktop\creepy\COM1.txt` | `61387` | `Stealthy file2` |
| `C:\Users\IEUser\Desktop\creepy\master.txt` | `61138` | `greetings from the master` |

## 2. ADS-hosted payloads and hashes

`istat` proves named `$DATA` attributes on both `welcome.txt` and `LPT1.txt`:

```text
$ istat -o 0 inputs/StealthyADS.E01 27771
Type: $DATA (128-1)   Name: N/A         Resident     size: 59
Type: $DATA (128-5)   Name: putty.exe   Non-Resident size: 809984

$ istat -o 0 inputs/StealthyADS.E01 27953
Type: $DATA (128-1)   Name: N/A         Resident     size: 16
Type: $DATA (128-4)   Name: putty.exe   Non-Resident size: 809984
```

Extracted and hashed artifacts from `work/extracted/sbe1803/`:

| Artifact | SHA-256 | Notes |
| --- | --- | --- |
| `creepy_putty.exe` | `5bf9bc242130a3d1cce7112167e51b5d356d9771093a26fb774dbcbe2bb90994` | standalone file `C:\Users\IEUser\Desktop\creepy\putty.exe` |
| `welcome_txt.putty.exe.ads` | `5bf9bc242130a3d1cce7112167e51b5d356d9771093a26fb774dbcbe2bb90994` | ADS `welcome.txt:putty.exe` |
| `LPT1_txt.putty.exe.ads` | `5bf9bc242130a3d1cce7112167e51b5d356d9771093a26fb774dbcbe2bb90994` | ADS `LPT1.txt:putty.exe` |
| `WELCOME.TXT_PUTTY.EXE-A6BB0639.pf.ads` | `03a1a3c4c414fc68f58ca67025966280eaee5083e4022b80b459955494c22b06` | hidden Prefetch ADS |
| `WELCOME2.TXT_REVSHELL.EXE-41B5A636.pf.ads` | `1661d820b23f4a7f4efc943cadbdddd4ef6f86f16b3b1a344678bb801ed7dbd8` | hidden Prefetch ADS |

`file` on the extracted PuTTY copies:

```text
work/extracted/sbe1803/creepy_putty.exe:       PE32 executable (GUI) Intel 80386, for MS Windows
work/extracted/sbe1803/welcome_txt.putty.exe.ads: PE32 executable (GUI) Intel 80386, for MS Windows
work/extracted/sbe1803/LPT1_txt.putty.exe.ads:    PE32 executable (GUI) Intel 80386, for MS Windows
```

The identical SHA-256 values show that both ADS payloads are byte-for-byte copies of the standalone `putty.exe` dropped in the same directory.

## 3. Stealthy hidden Prefetch ADS in `C:\Windows\Prefetch`

Catalog hits:

```text
54448:r/r 61166-128-1:    Windows/Prefetch/WELCOME.TXT
54449:r/r 61166-128-4:    Windows/Prefetch/WELCOME.TXT:PUTTY.EXE-A6BB0639.pf
54450:r/r 61167-128-1:    Windows/Prefetch/WELCOME2.TXT
54451:r/r 61167-128-4:    Windows/Prefetch/WELCOME2.TXT:REVSHELL.EXE-41B5A636.pf
```

`istat` confirms that each host file is a zero-byte default stream with a named non-resident ADS containing the real Prefetch data:

```text
$ istat -o 0 inputs/StealthyADS.E01 61166
Name: WELCOME.TXT
Type: $DATA (128-1)   Name: N/A                    Resident     size: 0
Type: $DATA (128-4)   Name: PUTTY.EXE-A6BB0639.pf Non-Resident size: 6462

$ istat -o 0 inputs/StealthyADS.E01 61167
Name: WELCOME2.TXT
Type: $DATA (128-1)   Name: N/A                        Resident     size: 0
Type: $DATA (128-4)   Name: REVSHELL.EXE-41B5A636.pf  Non-Resident size: 2703
```

I forged tool `prefetch_mam` to decompress and inspect these Windows 10 `MAM\x04` compressed Prefetch ADS. Results:

### `WELCOME.TXT:PUTTY.EXE-A6BB0639.pf`

```json
{
  "exe_name": "WELCOME.TXT:PUTTY.EXE",
  "last_runs": ["2019-05-26T08:41:32.929250Z"],
  "paths": [
    "\\VOLUME{01d4de9e09d44c1a-b009e7a9}\\USERS\\IEUSER\\DESKTOP\\CREEPY\\WELCOME.TXT:PUTTY.EXE"
  ]
}
```

### `WELCOME2.TXT:REVSHELL.EXE-41B5A636.pf`

```json
{
  "exe_name": "WELCOME2.TXT:REVSHELL.EXE",
  "last_runs": ["2019-05-26T08:41:52.069536Z"],
  "paths": [
    "\\VOLUME{01d4de9e09d44c1a-b009e7a9}\\USERS\\IEUSER\\DESKTOP\\CREEPY\\WELCOME2.TXT:REVSHELL.EXE"
  ]
}
```

These two artifacts answer the stealthy-case question directly: the attacker hid Prefetch records as ADS on decoy files `WELCOME.TXT` and `WELCOME2.TXT` inside `C:\Windows\Prefetch`, so a normal directory listing of `.pf` files would miss them even though they preserve execution evidence.

## 4. User interaction leftovers

Recent Items links were created at `2019-05-26T08:31:53Z`:

```text
554894:2019-05-26T08:31:53Z ... /Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/welcome.txt.lnk
554900:2019-05-26T08:31:53Z ... /Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/creepy.lnk
```

Extracted LNK details:

```text
work/extracted/sbe1803/welcome.txt.lnk: MS Windows shortcut ... Points to a file or directory ... length=59
work/extracted/sbe1803/creepy.lnk:      MS Windows shortcut ... Points to a file or directory ... Directory
```

`strings` on the LNK files recovers the targets:

```text
C:\Users\IEUser\Desktop\creepy\welcome.txt
C:\Users\IEUser\Desktop\creepy
```

This shows the user profile retained shell-link evidence for browsing the `creepy` folder and opening or at least resolving the `welcome.txt` lure.

## 5. Windows Defender detections

Defender history artifacts present on disk:

```text
1485:r/r 61466-128-4: ProgramData/Microsoft/Windows Defender/Scans/History/Service/DetectionHistory/06/B40DD859-99E0-4AB7-B7E9-C98FEEA7A890
1486:r/r 61566-128-1: ProgramData/Microsoft/Windows Defender/Scans/History/Service/Detections.log
1487:r/r 32791-128-3: ProgramData/Microsoft/Windows Defender/Scans/History/Service/History.Log
1488:r/r 80768-128-5: ProgramData/Microsoft/Windows Defender/Scans/History/Service/Unknown.Log
```

UTF-16 strings extracted from DetectionHistory file `B40DD859-99E0-4AB7-B7E9-C98FEEA7A890` show the malware family, paths, and shared payload hash:

```text
Trojan:Win32/Meterpreter.O
C:\Users\IEUser\Desktop\creepy\COM1.txt:revshell.exe
595e7bc6023702cb8692b67d3f0cebae35ef54ef6984ddbe2b37e9a407e2a1d9
C:\Users\IEUser\Desktop\creepy\rev.exe
595e7bc6023702cb8692b67d3f0cebae35ef54ef6984ddbe2b37e9a407e2a1d9
C:\Users\IEUser\Desktop\creepy\welcome2.txt:revshell.exe
595e7bc6023702cb8692b67d3f0cebae35ef54ef6984ddbe2b37e9a407e2a1d9
```

I also decoded the `ThreatTrackingStartTime` FILETIMEs in this record set during analysis and recorded them in the ledger:

- `2019-05-26T08:43:09.936856Z` — `COM1.txt:revshell.exe`
- `2019-05-26T08:43:12.638316Z` — `rev.exe`
- `2019-05-26T08:43:13.931214Z` — `welcome2.txt:revshell.exe`

So Defender **did** inspect and flag ADS-hosted malware, specifically the reverse-shell payload(s), and labeled them `Trojan:Win32/Meterpreter.O`.

## 6. Negative checks in my seat

I searched the catalog file list for common web-root / web-shell locations and for obvious attacker-created task/service names:

```bash
grep -nEi 'inetpub|wwwroot|xampp|apache|php|aspx|jsp|web\.config|shell\.aspx|cmdasp|c99|wso|shell' catalog/StealthyADS.E01/p0/filelist.txt | head
grep -nE '2019-05-26T08:.*(/Windows/System32/Tasks/|/Windows/Tasks/)' catalog/StealthyADS.E01/p0/timeline.csv | head -n 200
```

Result in this seat:

- no IIS/Apache/XAMPP web root or web-shell path stood out in the catalog output;
- no clearly attacker-created scheduled task was identified from these catalog searches;
- the task activity I did see around the attack window was dominated by built-in Microsoft task paths, including Windows Defender maintenance/scan tasks.

Those are negative findings only; if another seat finds corroborating registry/event-log evidence for persistence, that should override this limited catalog-only view.
