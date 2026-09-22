# Leftovers and malware findings (`s2f6603`)

## Scope

Assigned seat: web roots, temp and profile directories, prefetch, scheduled tasks, services, dropped tools and web shells; hashes for anything extracted.

I found no obvious attacker web root or web shell on disk from the catalog file list. The strongest leftover artifacts are user-land tools under `IEUser` and `Joker`, plus Windows Recent-link evidence proving both network-share access and the `AnotherPassword4U` image path.

## 1. Report-relevant findings

### 1.1 `AnotherPassword4U` image

There are **two local PNG copies** with the visible text `AnotherPassword4U`:

- `C:\Users\IEUser\Pictures\pics\whoami4.png` — inode `98748-128-3`
- `C:\Users\Joker\haha.png` — inode `97027-128-5`

The extracted files are byte-identical by SHA-256:

```text
c3b50a8bc1ba7cf2b87400e9d8cca93ca0291f42f11cfea5dda4dad9399e9a20  whoami4.png
c3b50a8bc1ba7cf2b87400e9d8cca93ca0291f42f11cfea5dda4dad9399e9a20  haha.png
```

Evidence chain:

1. I extracted and viewed `whoami4.png`.
2. I extracted and viewed `haha.png`.
3. I extracted the corresponding Recent-link file for `whoami4.png` and read its target metadata.
4. I pulled the file MAC timestamps from the catalog timeline.

Commands and outputs:

```bash
read work/extracted/s2f6603/whoami4.png
read work/extracted/s2f6603/haha.png
```

Output showed both PNGs with the same visible text:

```text
AnotherPassword4U
```

```bash
exiftool work/extracted/s2f6603/whoami4.png.lnk
```

Key output:

```text
Target File DOS Name            : whoami4.png
Drive Serial Number             : 68D6-28DB
Local Base Path                 : C:\Users\IEUser\Pictures\pics\whoami4.png
Working Directory               : C:\Users\IEUser\Pictures\pics
Machine ID                      : msedgewin10
```

```bash
grep -n 'Users/IEUser/Pictures/pics/whoami4.png' catalog/BSidesAmman21.E01/p0/timeline.csv
```

Output:

```text
4038:2018-03-06T16:33:54Z,2084,m...,r/rrwxrwxrwx,0,0,98748-128-3,"/Users/IEUser/Pictures/pics/whoami4.png"
451497:2019-02-15T05:06:52Z,2084,...b,r/rrwxrwxrwx,0,0,98748-128-3,"/Users/IEUser/Pictures/pics/whoami4.png"
451498:2019-02-15T05:06:52Z,88,macb,r/rrwxrwxrwx,0,0,98748-48-2,"/Users/IEUser/Pictures/pics/whoami4.png ($FILE_NAME)"
451512:2019-02-15T05:06:53Z,2084,.a..,r/rrwxrwxrwx,0,0,98748-128-3,"/Users/IEUser/Pictures/pics/whoami4.png"
451536:2019-02-15T05:07:07Z,2084,..c.,r/rrwxrwxrwx,0,0,98748-128-3,"/Users/IEUser/Pictures/pics/whoami4.png"
```

From the timeline above, `whoami4.png` MAC times in UTC are:

- Modified: `2018-03-06T16:33:54Z`
- Accessed: `2019-02-15T05:06:53Z`
- Created / metadata change shown in NTFS timeline: `2019-02-15T05:07:07Z`

Joker's duplicate file can also be shown directly from the timeline:

```bash
grep -n 'Users/Joker/haha.png' catalog/BSidesAmman21.E01/p0/filelist.txt
grep -n 'Users/Joker/haha.png' catalog/BSidesAmman21.E01/p0/timeline.csv
```

Output:

```text
8630:r/r 97027-128-5:	Users/Joker/haha.png
450588:2019-02-15T05:00:21Z,2084,m..b,r/rrwxrwxrwx,0,0,97027-128-5,"/Users/Joker/haha.png"
450589:2019-02-15T05:00:21Z,82,macb,r/rrwxrwxrwx,0,0,97027-48-6,"/Users/Joker/haha.png ($FILE_NAME)"
450590:2019-02-15T05:00:22Z,2084,.a..,r/rrwxrwxrwx,0,0,97027-128-5,"/Users/Joker/haha.png"
450629:2019-02-15T05:01:53Z,2084,..c.,r/rrwxrwxrwx,0,0,97027-128-5,"/Users/Joker/haha.png"
```

### 1.2 Confidential-picture access from a network share

`IEUser`'s Recent-link files show at least two accessed pictures came from a network share, not a local disk:

- `FindMeIfYouCan.jpg`
- `forensics.jpg`

Commands and outputs:

```bash
exiftool work/extracted/s2f6603/FindMeIfYouCan.jpg.lnk work/extracted/s2f6603/forensics.jpg.lnk
```

Key output for `FindMeIfYouCan.jpg.lnk`:

```text
Target File DOS Name            : FINDME~1.JPG
Net Name                        : \\192.168.70.128\SharedJJ
Working Directory               : O:\pics
```

Key output for `forensics.jpg.lnk`:

```text
Target File DOS Name            : FORENS~1.JPG
Net Name                        : \\192.168.70.128\SharedJJ
Working Directory               : O:\pics
```

Timeline support for those Recent links:

```bash
grep -n 'Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/FindMeIfYouCan.jpg.lnk' catalog/BSidesAmman21.E01/p0/timeline.csv
grep -n 'Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/forensics.jpg.lnk' catalog/BSidesAmman21.E01/p0/timeline.csv
```

Output:

```text
443302:2019-02-15T04:35:33Z,534,macb,r/rrwxrwxrwx,0,0,94989-128-1,"/Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/FindMeIfYouCan.jpg.lnk"
443303:2019-02-15T04:35:33Z,110,macb,r/rrwxrwxrwx,0,0,94989-48-2,"/Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/FindMeIfYouCan.jpg.lnk ($FILE_NAME)"
443332:2019-02-15T04:36:14Z,519,macb,r/rrwxrwxrwx,0,0,95048-128-1,"/Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/forensics.jpg.lnk"
443333:2019-02-15T04:36:14Z,100,macb,r/rrwxrwxrwx,0,0,95048-48-2,"/Users/IEUser/AppData/Roaming/Microsoft/Windows/Recent/forensics.jpg.lnk ($FILE_NAME)"
```

This is direct path evidence that the files were opened from mapped drive `O:` backed by UNC share `\\192.168.70.128\SharedJJ`.

### 1.3 `DCode.exe` location and timing

I can prove `DCode.exe` existed under Joker's profile:

- `C:\Users\Joker\DCode.exe`
- inode: `97020-128-5`

Command and output:

```bash
grep -n 'Users/Joker/DCode.exe' catalog/BSidesAmman21.E01/p0/filelist.txt
grep -n 'Users/Joker/DCode.exe' catalog/BSidesAmman21.E01/p0/timeline.csv
```

Output:

```text
8613:r/r 97020-128-5:	Users/Joker/DCode.exe
450563:2019-02-15T04:59:22Z,461952,...b,r/rrwxrwxrwx,0,0,97020-128-5,"/Users/Joker/DCode.exe"
450564:2019-02-15T04:59:22Z,84,...b,r/rrwxrwxrwx,0,0,97020-48-6,"/Users/Joker/DCode.exe ($FILE_NAME)"
450565:2019-02-15T04:59:23Z,461952,m.c.,r/rrwxrwxrwx,0,0,97020-128-5,"/Users/Joker/DCode.exe"
450566:2019-02-15T04:59:23Z,84,mac.,r/rrwxrwxrwx,0,0,97020-48-6,"/Users/Joker/DCode.exe ($FILE_NAME)"
450612:2019-02-15T05:01:40Z,461952,.a..,r/rrwxrwxrwx,0,0,97020-128-5,"/Users/Joker/DCode.exe"
```

Binary metadata from the extracted sample:

```bash
exiftool work/extracted/s2f6603/DCode.exe
```

Key output:

```text
Company Name                    : Digital Detective Group Ltd
File Description                : Hex/Numeric Value Date Time Decoder
Product Name                    : DCode
Original File Name              : DCode.exe
```

Important caution: from this seat alone I can prove **location** and **file timestamps**, but not safely attribute actual execution to Joker without corroborating evidence from other seats.

## 2. Other suspicious or investigation-relevant tools under user profiles

### 2.1 `IEUser` tools and traces

The following files existed under `IEUser`'s profile:

```bash
grep -nE 'Users/IEUser/\.ssh|Users/IEUser/Desktop/sync64\.exe|Users/IEUser/Downloads/putty\.exe|Users/IEUser/Downloads/SetMACE_v1009\.zip' catalog/BSidesAmman21.E01/p0/filelist.txt
```

Output:

```text
2980:d/d 89117-144-1:	Users/IEUser/.ssh
2981:r/r 94786-128-1:	Users/IEUser/.ssh/environment
6079:r/r 95992-128-1:	Users/IEUser/Desktop/sync64.exe
6088:r/r 87896-128-1:	Users/IEUser/Downloads/putty.exe
6095:r/r 87897-128-1:	Users/IEUser/Downloads/SetMACE_v1009.zip
```

The unpacked SetMACE files were also present:

```bash
grep -nE 'Users/IEUser/Downloads/SetMACE_v1009/SetMACE_v1009/(SetMace64\.exe|SetMace\.exe|readme\.txt|SetMace\.au3)' catalog/BSidesAmman21.E01/p0/filelist.txt
```

Output:

```text
6091:r/r 87900-128-3:	Users/IEUser/Downloads/SetMACE_v1009/SetMACE_v1009/readme.txt
6092:r/r 86837-128-3:	Users/IEUser/Downloads/SetMACE_v1009/SetMACE_v1009/SetMace.au3
6093:r/r 86846-128-3:	Users/IEUser/Downloads/SetMACE_v1009/SetMACE_v1009/SetMace.exe
6094:r/r 87901-128-4:	Users/IEUser/Downloads/SetMACE_v1009/SetMACE_v1009/SetMace64.exe
```

Binary/script metadata:

```bash
exiftool work/extracted/s2f6603/putty.exe work/extracted/s2f6603/sync64.exe work/extracted/s2f6603/SetMace.exe work/extracted/s2f6603/SetMace64.exe
strings -n 8 work/extracted/s2f6603/SetMace.au3 | head -n 20
```

Key output:

```text
putty.exe  -> File Description: SSH, Telnet and Rlogin client
sync64.exe -> Product Name: Sysinternals Sync
SetMace.exe / SetMace64.exe -> File Description: Change any file timestamp by using low level disk access
SetMace.au3 -> AutoIt source with comment: Timestamp manipulation
```

### 2.2 Prefetch evidence for those tools

Relevant prefetch files present in the catalog:

```bash
grep -nE 'Windows/Prefetch/(PUTTY|SCP|SDELETE|SETMACE|FTP|SSHD|POWERSHELL|NET1|NET|ROUTE|PING|REGSVR32|CHOCO|7Z|SYNC64).*' catalog/BSidesAmman21.E01/p0/filelist.txt
```

Output excerpt:

```text
41518:r/r 96113-128-4:	Windows/Prefetch/7Z.EXE-1EBD7D76.pf
41534:r/r 87974-128-4:	Windows/Prefetch/REGSVR32.EXE-B31EC963.pf
41538:r/r 88339-128-4:	Windows/Prefetch/ROUTE.EXE-121C5018.pf
41550:r/r 89969-128-4:	Windows/Prefetch/SSHD.EXE-EAF43813.pf
41560:r/r 90701-128-4:	Windows/Prefetch/FTP.EXE-3CF78E07.pf
41567:r/r 88394-128-4:	Windows/Prefetch/NET1.EXE-509326A5.pf
41577:r/r 87824-128-4:	Windows/Prefetch/PING.EXE-4A8A6853.pf
41578:r/r 88404-128-4:	Windows/Prefetch/POWERSHELL.EXE-CA1AE517.pf
41580:r/r 94978-128-4:	Windows/Prefetch/PUTTY.EXE-630D7EDB.pf
41583:r/r 89973-128-4:	Windows/Prefetch/SCP.EXE-183B9BDA.pf
41584:r/r 95003-128-4:	Windows/Prefetch/SDELETE.EXE-A820E9A7.pf
41590:r/r 87909-128-4:	Windows/Prefetch/SETMACE.EXE-A69E1686.pf
41599:r/r 87609-128-4:	Windows/Prefetch/NET.EXE-A0964F30.pf
41616:r/r 95993-128-4:	Windows/Prefetch/SYNC64.EXE-3630E8A8.pf
41645:r/r 92547-128-4:	Windows/Prefetch/CHOCO.EXE-15ADDBA1.pf
41646:r/r 92569-128-4:	Windows/Prefetch/CHOCO.EXE-94DFE012.pf
41756:r/r 97000-128-4:	Windows/Prefetch/PUTTY.EXE-64EA94A3.pf
41757:r/r 95050-128-4:	Windows/Prefetch/PUTTY.EXE-76653D18.pf
41758:r/r 98730-128-4:	Windows/Prefetch/PUTTY.EXE-EDC67D6E.pf
```

Timeline hits in the main 2019-02-15 window:

```bash
grep -nE 'Users/IEUser/Downloads/putty\.exe|Windows/Prefetch/PUTTY\.EXE-(630D7EDB|76653D18|64EA94A3|EDC67D6E)\.pf' catalog/BSidesAmman21.E01/p0/timeline.csv
grep -nE 'Users/IEUser/Desktop/sync64\.exe|Windows/Prefetch/SYNC64\.EXE-3630E8A8\.pf' catalog/BSidesAmman21.E01/p0/timeline.csv
grep -nE 'Users/IEUser/Downloads/SetMACE_v1009/SetMACE_v1009/(SetMace64\.exe|SetMace\.exe|readme\.txt|SetMace\.au3)' catalog/BSidesAmman21.E01/p0/timeline.csv
```

Key output excerpt:

```text
442969:2019-02-15T04:32:14Z,854072,...b,...,"/Users/IEUser/Downloads/putty.exe"
443284:2019-02-15T04:35:05Z,7025,ma.b,...,"/Windows/Prefetch/PUTTY.EXE-630D7EDB.pf"
443367:2019-02-15T04:38:19Z,7066,ma.b,...,"/Windows/Prefetch/PUTTY.EXE-76653D18.pf"
450675:2019-02-15T05:02:32Z,7090,ma.b,...,"/Windows/Prefetch/PUTTY.EXE-64EA94A3.pf"
451392:2019-02-15T05:05:12Z,10862,...b,...,"/Windows/Prefetch/PUTTY.EXE-EDC67D6E.pf"

443012:2019-02-15T04:33:19Z,10173,ma.b,...,"/Windows/Prefetch/SETMACE.EXE-A69E1686.pf"

443607:2019-02-15T04:52:15Z,158360,...b,...,"/Users/IEUser/Desktop/sync64.exe"
443615:2019-02-15T04:52:21Z,14938,...b,...,"/Windows/Prefetch/SYNC64.EXE-3630E8A8.pf"

442975:2019-02-15T04:32:52Z,121287,.ac.,...,"/Users/IEUser/Downloads/SetMACE_v1009/SetMACE_v1009/SetMace.au3"
442983:2019-02-15T04:32:54Z,654351,..c.,...,"/Users/IEUser/Downloads/SetMACE_v1009/SetMACE_v1009/SetMace.exe"
442991:2019-02-15T04:32:56Z,1162299,..c.,...,"/Users/IEUser/Downloads/SetMACE_v1009/SetMACE_v1009/SetMace64.exe"
443014:2019-02-15T04:33:25Z,654351,.a..,...,"/Users/IEUser/Downloads/SetMACE_v1009/SetMACE_v1009/SetMace.exe"
```

Interpretation: `IEUser` had several admin / anti-forensic / file-transfer tools staged or used in-profile during the attack window.

## 3. `.ssh` and other profile leftovers

### 3.1 `.ssh/environment`

`IEUser` had a `.ssh` directory containing an environment file.

Command and output:

```bash
icat inputs/BSidesAmman21.E01 94786 > work/extracted/s2f6603/ssh-environment.txt
cat work/extracted/s2f6603/ssh-environment.txt
```

Output:

```text
TEMP=C:\Windows\Temp
ProgramFiles(x86)=C:\Program Files (x86)
ProgramW6432=C:\Program Files
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files
CommonProgramW6432=C:\Program Files\Common Files
```

Timeline:

```bash
grep -n 'Users/IEUser/.ssh/environment' catalog/BSidesAmman21.E01/p0/timeline.csv
```

Output:

```text
215576:2018-04-25T20:06:45Z,206,m.cb,r/rrwxrwxrwx,0,0,94786-128-1,"/Users/IEUser/.ssh/environment"
215577:2018-04-25T20:06:45Z,88,macb,r/rrwxrwxrwx,0,0,94786-48-2,"/Users/IEUser/.ssh/environment ($FILE_NAME)"
217097:2018-04-25T20:13:25Z,206,.a..,r/rrwxrwxrwx,0,0,94786-128-1,"/Users/IEUser/.ssh/environment"
```

This is not by itself malicious, but it fits with the other SSH/PuTTY tooling.

## 4. Root-level script leftover

A root-level VBScript existed:

- `/temp.vbs`
- inode: `88378-128-1`

Command and output:

```bash
icat inputs/BSidesAmman21.E01 88378 > work/extracted/s2f6603/temp.vbs
cat work/extracted/s2f6603/temp.vbs
```

Output:

```vbscript
Set ServiceManager = CreateObject("Microsoft.Update.ServiceManager") 
Set NewUpdateService = ServiceManager.AddService2("7971f918-a847-4430-9279-4a52d1efe18d",7,"") 
```

Timeline:

```bash
grep -n 'temp.vbs' catalog/BSidesAmman21.E01/p0/timeline.csv
```

Output:

```text
197721:2018-04-25T20:01:37Z,168,m.cb,r/rrwxrwxrwx,0,0,88378-128-1,"/temp.vbs"
197722:2018-04-25T20:01:37Z,82,macb,r/rrwxrwxrwx,0,0,88378-48-2,"/temp.vbs ($FILE_NAME)"
442263:2019-02-15T04:19:55Z,168,.a..,r/rrwxrwxrwx,0,0,88378-128-1,"/temp.vbs"
```

There is also `CSCRIPT.EXE` prefetch in April 2018, but from this seat alone I cannot prove that `temp.vbs` was the script executed.

## 5. Scheduled tasks / services / web roots

### 5.1 Scheduled tasks

I found no obvious attacker-created scheduled task in `Windows/System32/Tasks`. I saw:

- built-in Microsoft task hierarchy
- `Windows/System32/Tasks/OneDrive Standalone Update Task v2`

Command:

```bash
grep -in 'System32/Tasks' catalog/BSidesAmman21.E01/p0/filelist.txt | head -n 200
```

And timeline spot-checks around the two main windows (`2018-04-25` and `2019-02-15`) only showed standard Microsoft task churn.

### 5.2 Services / web roots / web shells

From the catalog file list I did **not** identify a clear attacker web root such as `inetpub\wwwroot`, XAMPP install tree, or an obvious `.php` / `.aspx` web shell dropped under user-writable paths.

I did find browser-cache traces suggesting `IEUser` had viewed XAMPP-related web content:

```bash
grep -inE 'xampp|apache|htdocs|wwwroot|inetpub|php\.exe|php-cgi|phpmyadmin|mysql|mariadb|httpd\.exe' catalog/BSidesAmman21.E01/p0/filelist.txt | head -n 20
```

Output:

```text
5436:r/r 95795-128-4:	Users/IEUser/AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/AC/#!001/MicrosoftEdge/Cache/PPE43N99/bitnami-xampp[1].png
5442:r/r 95912-128-4:	Users/IEUser/AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/AC/#!001/MicrosoftEdge/Cache/PPE43N99/xampp-logo[1].svg
5452:r/r 98766-128-4:	Users/IEUser/AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/AC/#!001/MicrosoftEdge/Cache/U62FY5C0/backup-restore-mysql[1].htm
```

That shows browsing interest, not an installed XAMPP tree by itself.

## 6. Hashes of extracted artifacts

Commands:

```bash
cd work/extracted/s2f6603 && for f in DCode.exe putty.exe sync64.exe SetMace.au3 SetMace.exe SetMace64.exe FindMeIfYouCan.jpg FindMyLocation.jpg forensics.jpg Halloween.jpg Photo01.jpg Photo02.jpg Photo03.jpg python.png whoami4.png ZoteroWorkshopPoster.png FindMeIfYouCan.jpg.lnk forensics.jpg.lnk whoami4.png.lnk ssh-environment.txt temp.vbs; do sha256sum "$f"; done
```

Output:

```text
02b59b7ff4a5cd7a80f2c9c7d743af12850847c5a7448857e1a354490a8250b9  DCode.exe
7afb56dd48565c3c9804f683c80ef47e5333f847f2d3211ec11ed13ad36061e1  putty.exe
f40e850c892b3da81e2c4bbdf3e878e80557edd8a0e09c4dd9943cfdc8ad01d5  sync64.exe
d7940c04c3760d3c33c4f94d6eafdf1ba7fdea2e00c2f001fa008dc15eb17717  SetMace.au3
348ae744b18ac5f132e8f707eb4583b7913cda6168c3a39701db95f284164fc6  SetMace.exe
f736c2873e214059af28de6ef42b91dd5c033a0d6092bd3d68e66ec27b0f1d5b  SetMace64.exe
95284cd8891c1538f01dd1660d9416309880d7563875824ddd32d4da67d3bef6  FindMeIfYouCan.jpg
8e5d694c5cffba1d6817a201321bf46a6b998a7209450ddbd56dd7f69b748966  FindMyLocation.jpg
f743c025c1fe93240e3ac923656c3512c37308e3ea1b45689289088fb9fc2dab  forensics.jpg
7dc10787442997522bbffdad1503b1e92bef35bc07581dfe157c886a6c95e9fd  Halloween.jpg
05e8747a1644846bc837e1825eb23f40d6b7d4cea78483b97d37709d423ea128  Photo01.jpg
6e73237bc55df29a2e963b42a1527b2a4e28192d73339b724c303ef69586e327  Photo02.jpg
4a8fd497cd76adb9a055da43b3d00ff221cbd48790dbb011589c4aa61c7ba00a  Photo03.jpg
3ef9e4cfac6b8e50a97fb4ac024225056112e148731b4684bd6fc42653cd77eb  python.png
c3b50a8bc1ba7cf2b87400e9d8cca93ca0291f42f11cfea5dda4dad9399e9a20  whoami4.png
c3b50a8bc1ba7cf2b87400e9d8cca93ca0291f42f11cfea5dda4dad9399e9a20  haha.png
edf7de1384670ad947d1c3677344011e7e7aa519c6a2723616473a708b422430  ZoteroWorkshopPoster.png
dbb5b8db758cfe41d073fc7c0783c209e50106d1fbc99c7fc57e7daa76adc711  FindMeIfYouCan.jpg.lnk
f9f048ec033f111c0f8805dfda9bba1b477b2ca9390bbfc741531f6219da269f  forensics.jpg.lnk
7685f04bea5c522e39b0dbd9a0e5024daf766110d947a4fe7c083f8b08760a58  whoami4.png.lnk
a37f12cd639421366bb4f8a98c1263fdf1df89a948657d3b53e77a837b111164  ssh-environment.txt
928192bd3935e915f6dcfef42314a020526c6b09e1435f525e5b7fcc5d8d206f  temp.vbs
```

## 7. Bottom line

Most useful report contributions from this seat:

1. The `AnotherPassword4U` image exists in two local copies: `C:\Users\IEUser\Pictures\pics\whoami4.png` and `C:\Users\Joker\haha.png`. The `whoami4.png` Recent-link gives volume serial `68D6-28DB`.
2. `IEUser` opened at least `FindMeIfYouCan.jpg` and `forensics.jpg` from network share `\\192.168.70.128\SharedJJ` mapped as `O:\pics`.
3. `IEUser`'s profile contains PuTTY, SetMACE, Sync, and `.ssh` artifacts with corroborating prefetch evidence during the attack window.
4. `DCode.exe` was present under `C:\Users\Joker\DCode.exe`, but execution/user-attribution should be corroborated by another seat before final report language.