# Disk / Volume map — `inputs/s4a-challenge4`

## Partitions (`mmls inputs/s4a-challenge4`)

| Slot | Start sector | End sector | Length (sectors) | Description |
|------|-------------:|-----------:|-----------------:|-------------|
| 000 | 0 | 0 | 1 | Primary Table (MBR) |
| 001 | 0 | 2047 | 2048 | Unallocated |
| 002 | 2048 | 52426751 | 52424704 | NTFS (0x07) — the only data volume |
| 003 | 52426752 | 52428799 | 2048 | Unallocated |

Sector size 512 bytes; the NTFS volume is ~25 GB (52424704 sectors).

## Filesystem (`fsstat -o 2048`)

- FS type: **NTFS**
- Volume serial: `7A287C57287C13FB`
- OEM name: NTFS, "Version: Windows XP" (NTFS 3.1 on-disk format label)
- Cluster size 4096, MFT first cluster 786432, MFT entry size 1024
- Root directory inode: 5

## OS identification (from root directory contents)

Root contains: `bootmgr`, `Boot/`, `BOOTSECT.BAK`, `PerfLogs/`, `ProgramData/`,
`Program Files/`, `Users/`, `Documents and Settings/` (junction), `inetpub/`
(IIS), `$Recycle.Bin/`, `System Volume Information/`, plus `autoexec.bat`/
`config.sys`/`eula.*.txt` (Windows 7 install media leftovers).

=> This is a **Windows Server 2008 Standard SP1 (build 6001), 32-bit** layout with **IIS**
installed (`inetpub/` web root), not Windows XP despite the NTFS version label. (OS confirmed
via Volatility `windows.info` on the memory dump: `WIN-L0ZZQ76PMUF`, x86 PAE.)

## Notes / early indicators (from `fls -r -p`)

- Deleted entries: **2621** (see `work/filelist.txt`, lines containing `*`).
- Deleted webshell: `Users/Administrator/AppData/Local/Temp/c99 (2).php` — a
  classic PHP web shell (c99). Strong signal of a web compromise.
- `inetpub/` present — IIS web server in play.
- Administrator's Temporary Internet Files contain `xss_s[2].htm`,
  `login_logo[1].png`, `192_168_56_102[1].htm` — web/XSS testing activity
  from the Administrator profile (see deleted entries).
