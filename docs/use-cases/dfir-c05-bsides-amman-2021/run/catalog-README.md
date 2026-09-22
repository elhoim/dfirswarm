Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/BSidesAmman21.E01/partitions.txt` | no partition table: inputs/BSidesAmman21.E01 is a single NTFS volume | 1 | 113 B |
| `catalog/BSidesAmman21.E01/p0/fsstat.txt` | filesystem header at sector 0 (NTFS (logical volume, no partition table)) | 39 | 1.4 KB |
| `catalog/BSidesAmman21.E01/p0/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 275545 | 50.3 MB |
| `catalog/BSidesAmman21.E01/p0/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 0 inputs/BSidesAmman21.E01 <inode> | 143684 | 16.9 MB |
| `catalog/BSidesAmman21.E01/p0/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 458074 | 75.2 MB |
