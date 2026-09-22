Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/4orensics.001/partitions.txt` | no partition table: inputs/4orensics.001 is a single NTFS volume | 1 | 109 B |
| `catalog/4orensics.001/p0/fsstat.txt` | filesystem header at sector 0 (NTFS (logical volume, no partition table)) | 39 | 1.4 KB |
| `catalog/4orensics.001/p0/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 280524 | 49.6 MB |
| `catalog/4orensics.001/p0/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 0 inputs/4orensics.001 <inode> | 144156 | 16.1 MB |
| `catalog/4orensics.001/p0/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 468590 | 74.6 MB |
