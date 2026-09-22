Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

Segmented images: 5 further segment(s) belong to the set(s) catalogued above (BelkaCTF_6_CASE240405_LAPTOP.E01) and were not catalogued separately — libewf and The Sleuth Kit read the whole set from the first segment, so pass that one to every tool.

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/partitions.txt` | partition table of inputs/BelkaCTF_6_CASE240405_LAPTOP.E01 (mmls) | 13 | 717 B |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/fsstat.txt` | filesystem header at sector 673792 (Basic data partition) | 39 | 1.4 KB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 358879 | 64.8 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 673792 inputs/BelkaCTF_6_CASE240405_LAPTOP.E01 <inode> | 183296 | 21.1 MB |
| `catalog/BelkaCTF_6_CASE240405_LAPTOP.E01/p673792/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 624666 | 100.9 MB |
