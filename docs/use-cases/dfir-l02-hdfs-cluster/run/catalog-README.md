Summary: 3 disk image(s), 0 memory image(s), 15 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/HDFS-Master.E01/partitions.txt` | partition table of inputs/HDFS-Master.E01 (mmls) | 13 | 715 B |
| `catalog/HDFS-Master.E01/p2048/fsstat.txt` | filesystem header at sector 2048 (Linux (0x83)) | 7569 | 193.1 KB |
| `catalog/HDFS-Master.E01/p2048/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 190205 | 27.1 MB |
| `catalog/HDFS-Master.E01/p2048/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 2048 inputs/HDFS-Master.E01 <inode> | 190205 | 14.9 MB |
| `catalog/HDFS-Master.E01/p2048/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 599358 | 76.0 MB |
| `catalog/HDFS-Slave1.E01/partitions.txt` | partition table of inputs/HDFS-Slave1.E01 (mmls) | 13 | 715 B |
| `catalog/HDFS-Slave1.E01/p2048/fsstat.txt` | filesystem header at sector 2048 (Linux (0x83)) | 7568 | 193.0 KB |
| `catalog/HDFS-Slave1.E01/p2048/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 189659 | 27.0 MB |
| `catalog/HDFS-Slave1.E01/p2048/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 2048 inputs/HDFS-Slave1.E01 <inode> | 189659 | 14.9 MB |
| `catalog/HDFS-Slave1.E01/p2048/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 596715 | 75.8 MB |
| `catalog/HDFS-Slave2.E01/partitions.txt` | partition table of inputs/HDFS-Slave2.E01 (mmls) | 13 | 715 B |
| `catalog/HDFS-Slave2.E01/p2048/fsstat.txt` | filesystem header at sector 2048 (Linux (0x83)) | 7568 | 193.0 KB |
| `catalog/HDFS-Slave2.E01/p2048/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 189634 | 27.0 MB |
| `catalog/HDFS-Slave2.E01/p2048/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 2048 inputs/HDFS-Slave2.E01 <inode> | 189634 | 14.9 MB |
| `catalog/HDFS-Slave2.E01/p2048/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 596722 | 75.8 MB |

Not built:
- fls body file at sector 163579902: failed (exit 1: Cannot determine file system type )
- fls path list at sector 163579902: failed (exit 1: Cannot determine file system type )
- fls body file at sector 163579902: failed (exit 1: Cannot determine file system type )
- fls path list at sector 163579902: failed (exit 1: Cannot determine file system type )
- fls body file at sector 163579904: failed (exit 1: Cannot determine file system type )
- fls path list at sector 163579904: failed (exit 1: Cannot determine file system type )
- fls body file at sector 163579902: failed (exit 1: Cannot determine file system type )
- fls path list at sector 163579902: failed (exit 1: Cannot determine file system type )
- fls body file at sector 163579902: failed (exit 1: Cannot determine file system type )
- fls path list at sector 163579902: failed (exit 1: Cannot determine file system type )
- fls body file at sector 163579904: failed (exit 1: Cannot determine file system type )
- fls path list at sector 163579904: failed (exit 1: Cannot determine file system type )
- fls body file at sector 163579902: failed (exit 1: Cannot determine file system type )
- fls path list at sector 163579902: failed (exit 1: Cannot determine file system type )
- fls body file at sector 163579902: failed (exit 1: Cannot determine file system type )
- fls path list at sector 163579902: failed (exit 1: Cannot determine file system type )
- fls body file at sector 163579904: failed (exit 1: Cannot determine file system type )
- fls path list at sector 163579904: failed (exit 1: Cannot determine file system type )
