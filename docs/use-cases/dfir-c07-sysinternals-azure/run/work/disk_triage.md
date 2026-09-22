# Disk triage — ALIHADI-C7 / SysInternalsCase.E01

Seat: sd1d100. Evidence: catalog (no `mmls` rebuild), TSK `istat`/`icat` on selected inodes, strings from extracted PEs. All times below are **UTC** unless labelled local.

Extracts (quarantined): `work/extracted/disk/`  
Scratch (istat dumps): `work/sd1d100/`

---

## 1. Volume / filesystem

| Item | Value | Source |
| --- | --- | --- |
| Image | `inputs/SysInternalsCase.E01` (logical NTFS, no partition table) | `catalog/SysInternalsCase.E01/partitions.txt` |
| Use TSK | **without `-o`** (filesystem at sector 0) | catalog partitions.txt |
| FS type | NTFS, OEM `NTFS`, volume name **Windows 10** | `catalog/.../p0/fsstat.txt` |
| Volume serial | `BAB00A24B009E7A9` | fsstat.txt |
| Sector / cluster | 512 / 4096 | fsstat.txt |
| Sector range | 0–83881982 | fsstat.txt |
| MFT entry range | 0–126976 | fsstat.txt |
| Acquisition | FTK Imager 4.5.0.3, examiner AH, started 2022-11-15 13:32:05 (no TZ in txt) | `inputs/SysInternalsCase.E01.txt` |
| Image MD5 / SHA1 | `389ac32f7334160cf230bab6dc42d037` / `efe08e6806e34828255ad7ce45f57688594267e9` (verified) | E01.txt |

**Host local timezone (evidence system):** UTC−8. Windows artifacts stamped in local time (`ScreenOnPowerStudyTraceSession-2022-11-15-13-18-12.etl` at timeline `2022-11-15T21:18:12Z`; Defender `SHS-11152022-131622-...etl` at `21:16:22Z`). `istat` on this workstation prints `+03` (analyst TZ), not the evidence TZ. Catalog `timeline.csv` is UTC.

**Interactive user:** `IEUser` only (plus Default/Public). SID `S-1-5-21-321011808-3761883066-353627080-1000` (from `$Recycle.Bin` and NTFS security IDs on the download).

No memory image in this case (catalog summary: 0 memory images). `pagefile.sys` / `swapfile.sys` exist; see sd1d102.

---

## 2. What the user downloaded

The file is **not** the Sysinternals Suite. It is a 57 344-byte PE32 console downloader with a fake version resource.

| Field | Value |
| --- | --- |
| Display name | `SysInternals.exe` |
| Version resource | CompanyName `SysInternals, Inc.`; FileDescription **SysInternals Suite Downloader**; FileVersion `2.0.0.1`; OriginalFilename `SysInternals.exe`; Copyright `(C) 2020` |
| Type | PE32 executable (console) Intel 80386 |
| PE timestamp | 2020-11-18T19:09:04Z |
| Size | 57344 |
| SHA256 | `72e6d1728a546c2f3ee32c063ed09fa6ba8c46ac33b0dd2e354087c1ad26ef48` |
| MD5 | `d1a27b871a86c5371215f71885862cff` |
| Imports | `URLDownloadToFileA` (urlmon), `InternetOpenA`/`InternetOpenUrlA` (wininet), `ShellExecuteA`, `FreeConsole` |
| User-Agent string | `IE Agent 11.0` |

### Paths / inodes (proof)

| Path | Inode | Allocated? | MAC (UTC) | Notes |
| --- | --- | --- | --- | --- |
| `Users/IEUser/AppData/Local/Packages/Microsoft.MicrosoftEdge_8wekyb3d8bbwe/AC/#!001/MicrosoftEdge/Cache/WMFWC1O7/SysInternals[1].exe` | **124558**-128-4 | yes | 2022-11-15T21:18:40Z (all MACB) | Intact copy. Extract: `work/extracted/disk/SysInternals_inode124558.exe` |
| `Users/IEUser/.../TempState/Downloads/SysInternals.exe.51m0nh7.partial` | **124561**-128-4 | deleted | 21:18:40Z | Edge in-progress download; `icat` clusters reused (hash differs) |
| `Users/Public/Downloads/SysInternals.exe` | **124567**-128-4 | deleted | born 21:18:51Z; accessed/MFT 21:19:00Z | Save-As target (PickerHost prefetch same second). `icat` clusters reused. Object ID `eb87c52a-652a-11ed-a75d-000c292b044c`. Owner SID of IEUser |
| Edge `DownloadHistory/container.dat` | 124559-128-1 | yes | 21:18:40Z | Resident **size 0** — no URL here |

`istat` on 124558, 124561 and 124567 shows **no `$DATA` named `Zone.Identifier`**. MOTW ADS was not present on those MFT entries at collection.

**Download URL (WebCacheV01.dat, inode 83835, UTF-16):** `http://www.sysinternals.com/SysInternals.exe`
- Referer-style string `IEUser@http://www.sysinternals.com/SysInternals.exe`
- Tied to `SysInternals[1].exe` and `C:\Users\Public\Downloads\SysInternals.exe`
- HTTP response snippet: `HTTP/1.1 200 OK` `Date: Tue, 15 Nov 2022 18:18:40 GMT` (HTTP Date is 3h before NTFS 21:18:40Z — server clock labelled GMT, or a forged Date; NTFS/catalog times are authoritative for the host)
- Tool: `chunk_needles` on `work/extracted/WebCacheV01.dat` (offsets ~12058928, ~22021101)

This is **not** `https://download.sysinternals.com/` (the real suite). `www.sysinternals.com/SysInternals.exe` is the lure the user actually fetched.

Browser UI: `PICKERHOST.EXE-93018817.pf` (inode 124569, deleted) born 21:18:51Z — Save As into Public Downloads. `CHXSMARTSCREEN.EXE-54BF5C9A.pf` (124574) born 21:19:00Z — SmartScreen on the saved file (same second as last access on 124567).

---

## 3. XOR’d C2 / decoy URLs inside SysInternals.exe

ASCII blobs in `.rdata` decode with **XOR 0x41**:

| Encoded (excerpt) | Decoded |
| --- | --- |
| `)551{nn666o&..&-$o".,` | `http://www.google.com` (connectivity check, hypothesis) |
| `)5512{nn%."2o,("3.2.'5o".,n$/l42n282(/5$3/ -2n` | `https://docs.microsoft.com/en-us/sysinternals/` |
| `)551{nn666o, -6 3$urqo".,n)5,-n` | **`http://www.malware430.com/html/`** |
| `1% 5$o$9$` | `pdate.exe` (truncated `update.exe`) |
| `)5512{nn%.6/-. %o282(/5$3/ -2o".,n'(-$2n` | `https://download.sysinternals.com/files/` |

Cleartext (not XOR’d) in the same PE:

```
c:\Windows\vmtoolsIO.exe
c:\Windows\Temp\Hex2Dec.zip
cmd.exe
/C c:\Windows\vmtoolsIO.exe -install && net start VMwareIOHelperService && sc config VMwareIOHelperService start= auto
```

**Interpretation:** decoy fetch of a real Sysinternals zip (`Hex2Dec.zip` from `download.sysinternals.com/files/`) while the real payload is pulled from `malware430.com`. `Hex2Dec.zip` is **not** in the file list or 21:18–21:21 timeline (failed, never flushed, or deleted). Payload lands in the **WinINet/IE cache** as `VMwareUpdate[1].exe` (URLDownloadToFileA), then is copied to `C:\Windows\vmtoolsIO.exe`.

---

## 4. Payload and persistence on disk

### 4.1 WinINet cache copy (download of the second stage)

| Path | Inode | Size | MAC (UTC) |
| --- | --- | --- | --- |
| `Users/IEUser/AppData/Local/Microsoft/Windows/INetCache/IE/WNC4UP6F/VMwareUpdate[1].exe` | **81277**-128-4 | 289280 | 2022-11-15T21:19:17Z (all MACB) |

No Zone.Identifier ADS (`istat` 81277). Cache name implies remote filename **`VMwareUpdate.exe`**.

### 4.2 Dropped service binary

| Path | Inode | Size | SI times (UTC) |
| --- | --- | --- | --- |
| `Windows/vmtoolsIO.exe` | **82666**-128-4 | 289280 | created/modified 21:19:17Z; accessed 21:19:45Z |

`cmp` of icat 81277 vs 82666: **byte-identical**.

| Hash | Value |
| --- | --- |
| MD5 | `8c3ded1972755c8dc3c5b0ed200d7914` |
| SHA256 | `5b01cca415277e5fb0c454690142b9b4029a1566938875497d2f0593db555270` |
| Type | PE32 console 80386 |
| PE timestamp | 2020-11-18T19:10:20Z |
| Version | CompanyName `VMware, Inc.`; FileDescription `VMware Input & Output Helper Service`; FileVersion `3.2.0.1`; InternalName `vmtoolsIO.exe` |

This is a **new file** at `C:\Windows\vmtoolsIO.exe` (MFT created 21:19:17Z), not an in-place overwrite of `Program Files\VMware\VMware Tools\vmtoolsd.exe` (that legitimate binary still exists, inode 88666).

Strings / imports of interest:

- Service name `VMwareIOHelperService`, display `VMWare IO Helper Service`, account `NT AUTHORITY\SYSTEM`
- `-install` / `-remove`; `CreateServiceW`, `StartServiceCtrlDispatcherW`
- MSDN sample classes `CSampleService` / `CServiceBase`
- **`C:\Windows\Prefetch` + `*.pf`** together with `FindFirstFileW` / `FindNextFileW` / `DeleteFileW` / `QueueUserWorkItem` / `Sleep`

That last point is the on-disk explanation of the **slowdown** and of the **missing SysInternals prefetch**: the service enumerates and deletes prefetch files. Consistent with:

- `Windows/Prefetch/VMTOOLSIO.EXE-B05FE979.pf` inode **82668** born 21:19:22Z, **deleted**, `$DATA` `init_size: 0` (icat recovered zeros)
- No `SYSINTERNALS*.pf` anywhere in `filelist.txt`
- Large number of other `.pf` entries marked deleted in fls (many are older names; the service does not distinguish)

`CONSENT.EXE-65F6206D.pf` accessed 21:19:01Z — UAC likely for `sc config` / `net start` (dropper manifest is `asInvoker`). `CMD.EXE-EABFE48B.pf` accessed 21:19:21Z — matches the `cmd.exe /C ... -install && net start ...` line.

Service **registry** key is in SYSTEM (sd1d101): `ControlSet001\Services\VMwareIOHelperService`, ImagePath `c:\Windows\vmtoolsIO.exe`.

---

## 5. Attack-window file activity (2022-11-15 21:16–21:21 UTC)

Boot of this session is ~21:16:04Z (sd1d104). Infection is a **same-boot** event ~2.5 minutes later. Last hive writes ~21:21:13Z (imaging shortly after).

| UTC | What | Inode |
| --- | --- | --- |
| 21:16:04 | Session boot (Defender, VMware tools, LastGood) | (see timeline seat) |
| 21:18:40 | Edge caches `SysInternals[1].exe`; partial download created | 124558, 124561 |
| 21:18:51 | Saved to Public Downloads; PickerHost prefetch | 124567, 124569 |
| 21:18:53 | `RUNDLL32.EXE-A051DAB7.pf` born | 124570 |
| 21:18:58–21:19:00 | SmartScreen; last access on Public Downloads copy | 124574, 124567 |
| 21:19:01 | CONSENT.EXE prefetch accessed (UAC) | 124244 |
| 21:19:17 | `VMwareUpdate[1].exe` in IE cache **and** `Windows\vmtoolsIO.exe` created (identical) | 81277, 82666 |
| 21:19:21 | cmd.exe prefetch accessed; WinINet orphan INetCache dirs | 84312 |
| 21:19:22 | `VMTOOLSIO.EXE-B05FE979.pf` created then wiped | 82668 |
| 21:19:45 | `vmtoolsIO.exe` last accessed | 82666 |
| 21:21:13 | Registry hives / bootstat last writes | — |

`RUNDLL32.EXE-A051DAB7.pf` at 21:18:53 is **not** proven malware rundll32: it sits between Save-As and SmartScreen and may be MOTW/copy helper. Labelled hypothesis until prefetch body or 4688 says otherwise. Prefetch body is deleted/`init_size` 0.

---

## 6. Bonus: attacker-added / attacker-touched paths with inode proof

Only items born or overwritten in the 21:18–21:19 window that are tied to the download/dropper/payload. Not the pre-existing VMware Tools tree, chocolatey, or modern.ie noise.

| # | Path | Inode | State | Role |
| --- | --- | --- | --- | --- |
| 1 | `...\Edge\...\Cache\WMFWC1O7\SysInternals[1].exe` | 124558-128-4 | allocated | Stage 1 (Edge cache). Hashes above |
| 2 | `...\TempState\Downloads\SysInternals.exe.51m0nh7.partial` | 124561-128-4 | deleted | Stage 1 partial |
| 3 | `Users\Public\Downloads\SysInternals.exe` | 124567-128-4 | deleted | Stage 1 as saved by user |
| 4 | `...\INetCache\IE\WNC4UP6F\VMwareUpdate[1].exe` | 81277-128-4 | allocated | Stage 2 via WinINet (name VMwareUpdate.exe) |
| 5 | `Windows\vmtoolsIO.exe` | 82666-128-4 | allocated | Stage 2 on disk; service image |
| 6 | `Windows\Prefetch\VMTOOLSIO.EXE-B05FE979.pf` | 82668-128-4 | deleted, data gone | Proof of `-install` / service start |
| 7 | `Windows\Prefetch\PICKERHOST.EXE-93018817.pf` | 124569-128-4 | deleted | Save dialog |
| 8 | `Windows\Prefetch\CHXSMARTSCREEN.EXE-54BF5C9A.pf` | 124574-128-4 | deleted | SmartScreen |
| 9 | `Windows\Prefetch\RUNDLL32.EXE-A051DAB7.pf` | 124570-128-4 | deleted | See hypothesis above |
| 10 | `Windows\Temp\Hex2Dec.zip` | — | **not found** | Referenced by stage 1; no MFT hit |

`$Recycle.Bin` for this SID holds only `desktop.ini` — the Public Downloads copy was unlinked, not recycled.

---

## 7. Zone.Identifier / download URL (answer to critic / timeline seat)

- **No** `filename:Zone.Identifier` ADS on inodes 124558, 124561, 124567, or 81277 (`istat` attribute list).
- **Stage 1 URL (confirmed):** `http://www.sysinternals.com/SysInternals.exe` in `WebCacheV01.dat` (inode 83835) UTF-16, next to the Public Downloads path.
- **Stage 2 URL (confirmed):** `http://www.malware430.com/html/VMwareUpdate.exe` in the same ESE, next to `VMwareUpdate[1].exe` and `HTTP/1.1 200 OK` (offset ~14688786). Matches XOR 0x41 in the dropper.
- **Not an IOC:** `downloads.subscriptionsint.tfsallin.net` appears only inside an Edge/Microsoft host allow-list blob (powerbi, visualstudio, `download.sysinternals.com`). Do not cite it as the download source.
- Edge DBs: `spartan.edb` inode 84274; `WebCacheV01.dat` inode 83835.

---

## 8. Commands used (reproducible)

```
istat inputs/SysInternalsCase.E01 124558   # also 124561 124567 124559 82666 82668 81277
icat  inputs/SysInternalsCase.E01 124558 > work/extracted/disk/SysInternals_inode124558.exe
icat  inputs/SysInternalsCase.E01 81277  > work/extracted/disk/VMwareUpdate_inode81277.exe
icat  inputs/SysInternalsCase.E01 82666  > work/extracted/disk/vmtoolsIO_inode82666.exe
```

Catalog greps: `catalog_search` / `catalog_grep` over `filelist.txt` and `timeline.csv`.

---

## 9. Open items for other seats

- **sd1d101:** 7045 for `VMwareIOHelperService`; 4688 for `SysInternals.exe`, `cmd.exe`, `vmtoolsIO.exe`; SYSTEM `\Services\VMwareIOHelperService`.
- **sd1d103:** confirm Hex2Dec.zip absent in Temp; prefetch wipe as leftovers; hash extracts (duplicates of this seat’s files are OK).
- **sd1d104:** events listed in §5; do not treat RUNDLL32 as confirmed malware loader without 4688.
- **sd1d106:** XOR URLs **are** in the stage-1 PE (not “no URL”). `vmtoolsIO.exe` is a **drop**, not a replace of `vmtoolsd.exe`.
