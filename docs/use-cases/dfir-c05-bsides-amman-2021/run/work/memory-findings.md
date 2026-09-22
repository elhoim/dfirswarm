# Memory forensics findings — s2f6602

## Scope note

The evidence set does **not** include a standalone memory image. `SWARM.md` and the evidence catalog explicitly say `0 memory image(s)`, so classic Volatility 3 analysis is not possible from the provided inputs.

What does exist on the NTFS volume:

- `pagefile.sys` — inode `83404-128-1`
- `swapfile.sys` — inode `83405-128-1`

Evidence:

```text
read catalog/BSidesAmman21.E01/partitions.txt
read catalog/BSidesAmman21.E01/p0/fsstat.txt
grep -RinEi 'pagefile|swapfile' catalog/BSidesAmman21.E01/p0
```

Relevant output excerpts:

```text
No partition table: inputs/BSidesAmman21.E01 is one NTFS volume starting at sector 0
Volume Serial Number: EE68D66268D628DB
catalog/.../filelist.txt:24578:r/r 83405-128-1:	swapfile.sys
catalog/.../filelist.txt:143684:r/r 83404-128-1:	pagefile.sys
```

## High-value findings from memory-adjacent/user-state artifacts

### 1. Joker accessed the confidential files from a network share

Joker's `Recent` folder contains four LNK files for the confidential documents, and each LNK resolves to the SMB share `\\192.168.70.128\SharedJJ\docs`.

Artifacts:

- `Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential.lnk` — inode `96881-128-4`
- `Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_02.lnk` — inode `96884-128-4`
- `Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_03.lnk` — inode `96885-128-4`
- `Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_04.lnk` — inode `96886-128-4`

Extraction and analysis commands:

```bash
icat inputs/BSidesAmman21.E01 96881-128-4 > work/s2f6602/Confidential.lnk
icat inputs/BSidesAmman21.E01 96884-128-4 > work/s2f6602/Confidential_02.lnk
icat inputs/BSidesAmman21.E01 96885-128-4 > work/s2f6602/Confidential_03.lnk
icat inputs/BSidesAmman21.E01 96886-128-4 > work/s2f6602/Confidential_04.lnk
exiftool work/s2f6602/Confidential*.lnk
strings work/s2f6602/Confidential*.lnk
```

Key output excerpts:

```text
Net Name              : \\192.168.70.128\SHAREDJJ
Working Directory     : \\192.168.70.128\SharedJJ\docs
\\192.168.70.128\SharedJJ\docs\Confidential.rtf
\\192.168.70.128\SharedJJ\docs\Confidential_02.docx
\\192.168.70.128\SharedJJ\docs\Confidential_03.docx
\\192.168.70.128\SharedJJ\docs\Confidential_04.docx
```

Timeline support from `catalog/BSidesAmman21.E01/p0/timeline.csv`:

```text
2019-02-15T05:02:56Z ... /Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential.lnk
2019-02-15T05:03:34Z ... /Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_02.lnk
2019-02-15T05:03:39Z ... /Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_03.lnk
2019-02-15T05:03:45Z ... /Users/Joker/AppData/Roaming/Microsoft/Windows/Recent/Confidential_04.lnk
```

### 2. WordPad was used in the same activity window

Joker's `NTUSER.DAT` UserAssist records `wordpad.exe` as executed during the same minute as the confidential-document LNK activity.

Artifact:

- `Users/Joker/NTUSER.DAT` — inode `95995-128-4`

Extraction and analysis command:

```bash
icat inputs/BSidesAmman21.E01 95995-128-4 > work/s2f6602/Joker-NTUSER.DAT
python3 - <<'PY'
from regipy.registry import RegistryHive
from regipy.plugins.ntuser.user_assist import UserAssistPlugin
h=RegistryHive('work/s2f6602/Joker-NTUSER.DAT')
p=UserAssistPlugin(h, as_json=True)
p.run()
for e in p.entries:
    if 'wordpad' in e.get('name','').lower():
        print(e)
PY
```

Key output excerpt:

```text
{'name': '%PROGRAMFILES%\\Windows NT\\Accessories\\wordpad.exe',
 'timestamp': '2019-02-15T05:03:45.634000+00:00',
 'run_counter': 5,
 'focus_count': 4,
 'total_focus_time_ms': 22516,
 'session_id': 0}
```

This supports the report answer that **WordPad** was an application used to open at least one of the confidential documents.

### 3. DCode.exe: solved via the renamed copy `dd.exe`

Artifact on disk:

- `Users/Joker/DCode.exe` — inode `97020-128-5`

Catalog evidence:

```text
catalog/.../filelist.txt:8613:r/r 97020-128-5:	Users/Joker/DCode.exe
2019-02-15T04:59:22Z ... /Users/Joker/DCode.exe
2019-02-15T04:59:23Z ... /Users/Joker/DCode.exe
2019-02-15T05:01:40Z ... /Users/Joker/DCode.exe
```

Commands used:

```bash
grep -Ein 'DCode\.exe|DCode' catalog/BSidesAmman21.E01/p0/filelist.txt | head -50
grep -n '/Users/Joker/DCode\.exe"' catalog/BSidesAmman21.E01/p0/timeline.csv
python3 - <<'PY'
from regipy.registry import RegistryHive
from regipy.plugins.ntuser.user_assist import UserAssistPlugin
for path in ['work/s2f6602/IEUser-NTUSER.DAT','work/s2f6602/Joker-NTUSER.DAT']:
    h=RegistryHive(path)
    p=UserAssistPlugin(h, as_json=True)
    p.run()
    print('\nFILE', path)
    for e in p.entries:
        if 'DCode' in e.get('name',''):
            print(e)
PY
grep -Ein 'DCode.*\.pf|DCODE.*\.PF' catalog/BSidesAmman21.E01/p0/filelist.txt || true
```

Corroborating cross-seat evidence from `s2f6601`:

```text
KEY=ROOT\Software\VB and VBA Program Settings\DCode\Settings
  last_modified_utc=2019-02-15T05:02:13.494426+00:00
  Value(name='OnTop', value='False', value_type='REG_SZ', ...)
```

My additional verification:

```bash
icat inputs/BSidesAmman21.E01 97020-128-5 > work/s2f6602/extracted/DCode.exe
icat inputs/BSidesAmman21.E01 97026-128-5 > work/s2f6602/extracted/dd.exe
md5 work/s2f6602/extracted/DCode.exe work/s2f6602/extracted/dd.exe
shasum -a 256 work/s2f6602/extracted/DCode.exe work/s2f6602/extracted/dd.exe
```

Output:

```text
MD5 (work/s2f6602/extracted/DCode.exe) = b534d93d94f86a052f398a44928247d9
MD5 (work/s2f6602/extracted/dd.exe) = b534d93d94f86a052f398a44928247d9
02b59b7ff4a5cd7a80f2c9c7d743af12850847c5a7448857e1a354490a8250b9  work/s2f6602/extracted/DCode.exe
02b59b7ff4a5cd7a80f2c9c7d743af12850847c5a7448857e1a354490a8250b9  work/s2f6602/extracted/dd.exe
```

Joker `UserAssist` also contains the renamed binary:

```text
{'name': 'C:\\Users\\Joker\\dd.exe', 'timestamp': '2019-02-15T05:02:12.791000+00:00', 'run_counter': 1, 'focus_count': 1, 'total_focus_time_ms': 4110, 'session_id': 0}
```

I also extracted and parsed the Windows 10 prefetch file for the renamed executable:

```bash
icat inputs/BSidesAmman21.E01 96361-128-4 > work/s2f6602/DD.EXE-0C303FDD.pf
mam_pf_parse {"path":"work/s2f6602/DD.EXE-0C303FDD.pf"}
```

Output excerpt:

```json
{
  "version": 30,
  "signature": "SCCA",
  "executable_name": "DD.EXE",
  "prefetch_hash": "0C303FDD",
  "run_count": 1,
  "last_run_times_utc": ["2019-02-15T05:02:13.353878Z"]
}
```

Result:

- The original application file was present as `C:\Users\Joker\DCode.exe`.
- A byte-identical copy existed as `C:\Users\Joker\dd.exe`.
- The execution artifacts are attached to **`dd.exe`**, not `DCode.exe`.
- `s2f6601` found the `DCode` settings key modified inside **Joker's** `NTUSER.DAT` at `2019-02-15T05:02:13.494426Z`.
- I found **no DCode.exe prefetch file**, but I did find **DD.EXE prefetch** proving one run at `2019-02-15T05:02:13.353878Z`.

So the safest report answer is:

- **Which user ran DCode.exe?** Joker.
- **How many times?** 1 confirmed execution.
- **When last used?** `2019-02-15T05:02:13.353878Z` from Prefetch.
- **Where was the application located?** `C:\Users\Joker\DCode.exe`.
- **Why is it tricky?** The executable appears to have been launched under the renamed filename `dd.exe`, so the execution evidence shows `dd.exe` rather than `DCode.exe`.
## Useful cross-seat note

While inspecting Joker user-state artifacts, I also found a network tool execution lead:

```text
{'name': '\\\\192.168.70.128\\SharedJJ\\tools\\putty.exe',
 'timestamp': '2019-02-15T05:05:06.056000+00:00',
 'run_counter': 2,
 ...}
```

That came from Joker `NTUSER.DAT` UserAssist and may help correlate the network-share activity.
