Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/Webserver.E01/partitions.txt` | partition table of inputs/Webserver.E01 (mmls) | 13 | 719 B |
| `catalog/Webserver.E01/p2048/fsstat.txt` | filesystem header at sector 2048 (Linux (0x83)) | 425 | 10.5 KB |
| `catalog/Webserver.E01/p2048/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 324 | 28.5 KB |
| `catalog/Webserver.E01/p2048/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 2048 inputs/Webserver.E01 <inode> | 324 | 11.4 KB |
| `catalog/Webserver.E01/p2048/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 634 | 51.2 KB |

Not built:
- fls body file at sector 501758: failed (exit 1: Cannot determine file system type )
- fls path list at sector 501758: failed (exit 1: Cannot determine file system type )
- fls body file at sector 501758: failed (exit 1: Cannot determine file system type )
- fls path list at sector 501758: failed (exit 1: Cannot determine file system type )
- fls body file at sector 501760: failed (exit 1: Cannot determine file system type )
- fls path list at sector 501760: failed (exit 1: Cannot determine file system type )
