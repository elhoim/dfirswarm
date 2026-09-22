Summary: 1 disk image(s), 0 memory image(s), 5 catalog file(s)

| File | What | Rows | Size |
| --- | --- | --- | --- |
| `catalog/ThreatSimServer.E01/partitions.txt` | no partition table: inputs/ThreatSimServer.E01 is a single NTFS volume | 1 | 115 B |
| `catalog/ThreatSimServer.E01/p0/fsstat.txt` | filesystem header at sector 0 (NTFS (logical volume, no partition table)) | 39 | 1.4 KB |
| `catalog/ThreatSimServer.E01/p0/bodyfile.txt` | body file (fls -m -r), every file with MAC times, for mactime/grep | 1058248 | 248.4 MB |
| `catalog/ThreatSimServer.E01/p0/filelist.txt` | path list (fls -r -p): inode, type and full path per line; icat -o 0 inputs/ThreatSimServer.E01 <inode> | 543927 | 89.4 MB |
| `catalog/ThreatSimServer.E01/p0/timeline.csv` | MAC timeline (mactime -d -y): date, size, MACB, mode, uid, gid, inode, name — UTC | 2082611 | 456.8 MB |
