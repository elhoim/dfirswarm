Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/workshop-kali.E01/partitions.txt` | partition table of inputs/workshop-kali.E01 (mmls) | 13 | 715 B |
| `catalog/workshop-kali.E01/p2048/fsstat.txt` | filesystem header at sector 2048 (Linux (0x83)) | 8819 | 239.7 KB |
| `catalog/workshop-kali.E01/p2048/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 870917 | 120.7 MB |
| `catalog/workshop-kali.E01/p2048/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 2048 inputs/workshop-kali.E01 <inode> | 870917 | 65.1 MB |
| `catalog/workshop-kali.E01/p2048/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 2427769 | 302.1 MB |

Not built:
- fls body file at sector 163581950: failed (exit 1: Cannot determine file system type )
- fls path list at sector 163581950: failed (exit 1: Cannot determine file system type )
- fls body file at sector 163581950: failed (exit 1: Cannot determine file system type )
- fls path list at sector 163581950: failed (exit 1: Cannot determine file system type )
- fls body file at sector 163581952: failed (exit 1: Cannot determine file system type )
- fls path list at sector 163581952: failed (exit 1: Cannot determine file system type )
