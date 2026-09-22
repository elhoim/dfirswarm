Summary: 1 disk image(s), 1 memory image(s), 12 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/memdump.mem/windows.info.txt` | OS, build, capture time of inputs/memdump.mem (vol windows.info) | 27 | 792 B |
| `catalog/memdump.mem/pslist.txt` | vol windows.pslist over inputs/memdump.mem | 46 | 3.8 KB |
| `catalog/memdump.mem/psscan.txt` | vol windows.psscan over inputs/memdump.mem | 46 | 3.8 KB |
| `catalog/memdump.mem/cmdline.txt` | vol windows.cmdline over inputs/memdump.mem | 46 | 2.8 KB |
| `catalog/memdump.mem/netscan.txt` | vol windows.netscan over inputs/memdump.mem | 81 | 5.7 KB |
| `catalog/memdump.mem/malfind.txt` | vol windows.malfind over inputs/memdump.mem | 34 | 3.3 KB |
| `catalog/memdump.mem/dlllist.txt` | vol windows.dlllist over inputs/memdump.mem | 1974 | 185.2 KB |
| `catalog/s4a-challenge4/partitions.txt` | partition table of inputs/s4a-challenge4 (mmls) | 9 | 418 B |
| `catalog/s4a-challenge4/p2048/fsstat.txt` | filesystem header at sector 2048 (NTFS / exFAT (0x07)) | 39 | 1.4 KB |
| `catalog/s4a-challenge4/p2048/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 134075 | 21.2 MB |
| `catalog/s4a-challenge4/p2048/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 2048 inputs/s4a-challenge4 <inode> | 68332 | 6.4 MB |
| `catalog/s4a-challenge4/p2048/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 219722 | 30.8 MB |
