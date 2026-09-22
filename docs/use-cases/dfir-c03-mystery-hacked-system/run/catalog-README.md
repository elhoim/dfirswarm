Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/Windows8.1-Challenge3.001/partitions.txt` | no partition table: inputs/Windows8.1-Challenge3.001 is a single NTFS volume | 1 | 121 B |
| `catalog/Windows8.1-Challenge3.001/p0/fsstat.txt` | filesystem header at sector 0 (NTFS (logical volume, no partition table)) | 39 | 1.4 KB |
| `catalog/Windows8.1-Challenge3.001/p0/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 227399 | 41.6 MB |
| `catalog/Windows8.1-Challenge3.001/p0/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 0 inputs/Windows8.1-Challenge3.001 <inode> | 117169 | 13.8 MB |
| `catalog/Windows8.1-Challenge3.001/p0/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 396327 | 65.3 MB |
