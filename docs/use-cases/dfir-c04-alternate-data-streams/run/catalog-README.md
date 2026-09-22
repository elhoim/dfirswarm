Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/StealthyADS.E01/partitions.txt` | no partition table: inputs/StealthyADS.E01 is a single NTFS volume | 1 | 111 B |
| `catalog/StealthyADS.E01/p0/fsstat.txt` | filesystem header at sector 0 (NTFS (logical volume, no partition table)) | 40 | 1.4 KB |
| `catalog/StealthyADS.E01/p0/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 314100 | 60.3 MB |
| `catalog/StealthyADS.E01/p0/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 0 inputs/StealthyADS.E01 <inode> | 164443 | 20.9 MB |
| `catalog/StealthyADS.E01/p0/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 568964 | 98.7 MB |
