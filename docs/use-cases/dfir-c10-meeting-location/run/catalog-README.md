Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/Case4.E01/partitions.txt` | partition table of inputs/Case4.E01 (mmls) | 9 | 418 B |
| `catalog/Case4.E01/p2048/fsstat.txt` | filesystem header at sector 2048 (NTFS / exFAT (0x07)) | 40 | 1.4 KB |
| `catalog/Case4.E01/p2048/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 333805 | 64.6 MB |
| `catalog/Case4.E01/p2048/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 2048 inputs/Case4.E01 <inode> | 175896 | 22.6 MB |
| `catalog/Case4.E01/p2048/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 598284 | 104.8 MB |
