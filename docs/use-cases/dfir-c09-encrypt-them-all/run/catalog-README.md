Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/AF-Case2.E01/partitions.txt` | no partition table: inputs/AF-Case2.E01 is a single NTFS volume | 1 | 108 B |
| `catalog/AF-Case2.E01/p0/fsstat.txt` | filesystem header at sector 0 (NTFS (logical volume, no partition table)) | 40 | 1.4 KB |
| `catalog/AF-Case2.E01/p0/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 313227 | 60.0 MB |
| `catalog/AF-Case2.E01/p0/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 0 inputs/AF-Case2.E01 <inode> | 163914 | 20.8 MB |
| `catalog/AF-Case2.E01/p0/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 580364 | 100.7 MB |
