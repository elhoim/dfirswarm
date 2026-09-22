Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/SysInternalsCase.E01/partitions.txt` | no partition table: inputs/SysInternalsCase.E01 is a single NTFS volume | 1 | 116 B |
| `catalog/SysInternalsCase.E01/p0/fsstat.txt` | filesystem header at sector 0 (NTFS (logical volume, no partition table)) | 40 | 1.4 KB |
| `catalog/SysInternalsCase.E01/p0/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 314121 | 60.3 MB |
| `catalog/SysInternalsCase.E01/p0/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 0 inputs/SysInternalsCase.E01 <inode> | 164453 | 20.9 MB |
| `catalog/SysInternalsCase.E01/p0/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 565713 | 98.1 MB |
