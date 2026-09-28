# The tool library

Forty-one tools. Thirty-five were written by agents: thirty-two during the
forensic cases in [docs/use-cases](../docs/use-cases/README.md), and three in
later runs, folded in and made general ([below](#folded-from-later-runs));
six were written for gaps those cases left, and are marked `maintainer` in
the table. Each is a directory with a manifest and a script.

Hand it to a run and every agent has them from its first turn:

```bash
scripts/swarm.sh start … --tools-from tool-library
```

and put a finished run's own tools back with
`scripts/swarm.sh tools <id> --save tool-library`.

**Read them before you use them.** The agent-written ones were written by a
model in the middle of a case, they were useful enough to be called and to
survive into the next run, and nobody reviewed them line by line. Inside a
swarm they run in the sandbox with the same limits as `bash`; outside one they
are ordinary scripts on your machine. The eleventh case forged nothing at all
because this library already covered it, which is the argument for keeping
them, not for trusting them blindly.

**What the corpus says about them.** Across the eighteen traces under
`docs/use-cases`, `catalog_grep` was called 152 times, `regkv` 84 and
`evtx_query` 64; four — `aescrypt_v2_decrypt`, `extract_stream`, `icat_root`
and `volrun` — were never called at all. That is a measurement, not a verdict:
three of the four were written late, and one of them is the only AES Crypt
implementation here. They stay.

**Every tool works on more than one case.** Three used to hard-code the image
they were written for — `icat_root`, `master_icat` and `hdfs_node_icat` — so
they were unusable on any other. Those filenames are defaults now, and
`image` and `offset` name any other image. A tool that can only ever read one
image is a tool the next run has to write again, which is the argument
against the library rather than for it.

**A tool says which programs it runs.** A manifest's `requires` lists the
programs the script calls (`icat`, `fls`, `img_stat`, `esedbexport`, `yara`,
`vol`, `sqlite3`); the Python it imports is in
[images/library-python.txt](../images/library-python.txt), which every VM
image installs. Only `sqlite3` of those is in the base image, so
`images/recipe.py profile-for --tools-from tool-library` names an image
that has the rest (disk, today); `tests/recipe.test.sh` fails when a script
runs one of them without saying so.

**Three import what only some images have.** `contact_sheet` needs Pillow
(and pillow_heif for HEIC), which the mobile image carries; `nested_vdi`
needs pytsk3 to list and extract and pyewf for an E01, which the disk and
mobile images carry. None of the three is in `library-python.txt`, so the
tools import them by name when called and answer "Pillow is not installed" (or pytsk3, or
pyewf) rather than failing on an import line. The check that holds the
library's imports to `library-python.txt` does not see a module imported by
name; this paragraph is where those three say what they need.

**A page is not a cut.** The paged query tools (`amcache_apps`,
`browser_history`, `catalog_grep`, `csearch`, `esedb_query`,
`chunk_needles`, `evtx_filter`, `evtx_query`, `ftk_csv`,
`guest_syslog`, `ioc_scan`, `lnk_parse`, `mam_scan`, `nested_vdi` (its
`ls`), `prefetch_mam`, `recyclebin_i`, `sig_carve`, `sigscan_e01`,
`usn_journal`, and `utf16_urls`) still scan the whole source. They return the requested first
page and, when more matches exist, atomically keep the complete result as JSON
Lines under `work/<agent>/tool-output/`; `all_results` (or the corresponding
nested page record) names that file. A result's `matched` count is therefore
the whole set, while `returned` is only the inline page. The shared
implementation is `_output.py`.

| Tool | Runtime | Written by | v | What it does |
| --- | --- | --- | --- | --- |
| `aescrypt_v2_decrypt` | python3 | `s864a02` | 3 | Decrypt AES Crypt 3.10 Windows GUI v2 files (KDF: SHA256(IV||zeros16||UTF16LE pw)×8192). Returns plaintext pa… |
| `amcache_apps` | python3 | `maintainer` | 1 | Program execution from Amcache.hve: path, SHA-1, publisher and link date, from whichever of the Windows 7/8 a… |
| `browser_history` | python3 | `maintainer` | 2 | Query a browser history database, copying it and any -wal beside it first so the write-ahead log is replayed … |
| `catalog_grep` | python3 | `s864a02` | 1 | Grep catalog/AF-Case2.E01/p0/filelist.txt for a pattern; return matching lines. |
| `catalog_search` | python3 | `sd1d100` | 9 | Search the evidence catalogue with a regex: a disk's filelist, timeline, bodyfile, fsstat or partitions, or a… |
| `check_inputs` | python3 | `sfcc304` | 2 | Diff inputs/ against inputs.json (size and sha256). Fails if the manifest is missing or any file differs. |
| `chunk_needles` | python3 | `sd1d102` | 3 | Scan a local file (or icat an inode from the E01) for ASCII/UTF-16 needles; return hit counts and nearby snip… |
| `contact_sheet` | python3 | `s10d40e` | 1 | Tile many images into labelled contact sheets to look at: a directory, a list of paths or a tar read in place… |
| `csearch` | python3 | `sf6df06` | 2 | Search the kickoff catalog files (filelist/timeline/bodyfile/pslist/cmdline/netscan/malfind/dlllist/psscan) f… |
| `esedb_query` | python3 | `maintainer` | 3 | Read an ESE database (WebCacheV01.dat, SRUDB.dat, spartan.edb) as tables via esedbexport. Lists the tables, o… |
| `evtx_filter` | python3 | `sd1d101` | 1 | Parse a local EVTX; return EventID/TimeCreated/EventData for matching IDs or a time prefix |
| `evtx_query` | python3 | `sbe1801` | 1 | Parse an EVTX file and return filtered events with timestamp, event_id, channel, computer, record_id, and nam… |
| `extract_stream` | bash | `sfcc303` | 2 | Extract a data stream from an NTFS E01 image using icat. Returns the raw bytes (base64-encoded); a failure co… |
| `file_carver` | python3 | `s183904` | 2 | Carve files from a raw binary dump by header/footer signatures. Given a path, an offset, and a signature type… |
| `fls_root` | python3 | `s9d8306` | 2 | Run fls on an EXT4 volume (default offset 503808, image inputs/Webserver.E01). Reads inode/recursive/image/of… |
| `ftk_csv` | python3 | `s9d8303` | 1 | Query the UTF-16 FTK Imager CSV for path/date/deleted filters; return matching rows as JSON. |
| `fve_metadata` | python3 | `s864a05` | 2 | Parse a BitLocker -FVE-FS- volume (raw image or VHD partition) and return metadata: GUID, encryption method, … |
| `grep_filelist` | python3 | `s864a08` | 4 | Search the catalog filelist for a pattern (case-insensitive). Returns the first 100 matching lines as a JSON … |
| `guest_syslog` | python3 | `s5d1001` | 1 | Extract unique syslog-like lines from a binary (Kali/rsyslog) matching a month-day prefix; drop kernel lines. |
| `hdfs_node_icat` | python3 | `s9a5f03` | 2 | Extract an inode from a cluster node's image with icat and hash what it wrote. node picks one of the HDFS cas… |
| `icat_extract` | python3 | `s864a08` | 3 | Extract a file from the E01 image by inode to a specified output path. Returns JSON with path, size, and sha2… |
| `icat_root` | python3 | `s9d8306` | 5 | Extract an inode from an EXT4 volume with icat. The Webserver case's image and its 503808-sector offset are t… |
| `ioc_scan` | python3 | `s183900` | 3 | Stream a large binary for ASCII and UTF-16LE needles; return offsets, unique strings, and context snippets. |
| `ledger_timeline` | python3 | `se5fdcd` | 3 | Write a run's dated ledger entries as one timeline in time order (Markdown table, CSV or JSON Lines). Leaves … |
| `lnk_parse` | python3 | `s183902` | 2 | Parse a Windows LNK (or a dump slice) and return flags, FILETIME timestamps, local/common paths, arguments, a… |
| `mam_pf_parse` | python3 | `s2f6600` | 1 | Decompress a MAM-wrapped Windows prefetch file and return executable name, version, run count, and non-zero l… |
| `mam_scan` | python3 | `s183901` | 1 | Scan a raw dump for MAM\x04 prefetch, decompress LZXPRESS Huffman, return name, run count, last-run FILETIMEs… |
| `master_icat` | bash | `s9a5f06` | 3 | Extract a file by inode from an E01 with icat. The HDFS master image and sector offset 2048 are the defaults;… |
| `nested_vdi` | python3 | `sae6e7d` | 1 | Read a VirtualBox VDI that lies inside an E01 or raw image, in place: found by its NTFS data runs (a deleted … |
| `prefetch_mam` | python3 | `sbe1803` | 2 | Decompresses MAM-compressed or plain Windows Prefetch files and returns header fields, last-run FILETIMEs, an… |
| `recyclebin_i` | python3 | `maintainer` | 1 | Parse $Recycle.Bin $I metadata: original path, original size and deletion time, for one file or every $I unde… |
| `reg_hive_query` | python3 | `sbe1805` | 1 | Query a Windows registry hive file (regipy) and return a key's values and subkey names as JSON. |
| `regkeys` | python3 | `sf4b205` | 4 | Dump a registry key's values and subkeys from a hive with regipy. Text values are decoded, REG_BINARY comes b… |
| `regkv` | python3 | `s9f2005` | 3 | Read a Windows registry hive with regipy and dump a key's values plus subkeys with their last-modified (FILET… |
| `sig_carve` | python3 | `s183906` | 1 | Scan a binary file for multiple file signatures (magic bytes) and return offsets, context, and estimated size… |
| `sigscan_e01` | python3 | `s5d1001` | 3 | Scan an E01/raw image for a byte signature via TSK img_cat (logical media, not the EWF wrapper). Returns offs… |
| `sqlite_query` | python3 | `s881002` | 4 | Run a read-only sqlite3 query against a database file and return stdout/stderr plus exit code. |
| `usn_journal` | python3 | `maintainer` | 2 | Parse an NTFS change journal ($UsnJrnl:$J) into records: name, USN, timestamp, reason bits and file reference… |
| `utf16_urls` | python3 | `s5d1003` | 1 | Extract UTF-16LE and ASCII URL/Visited strings from a local file; filter optional substrings. Returns unique … |
| `volrun` | python3 | `s69d306` | 2 | Run a Volatility 3 plugin against a memory image with typed arguments. Returns stdout/stderr. |
| `yara_scan` | python3 | `maintainer` | 1 | Sweep a file or directory with a YARA rule file and report every match with its offset. No rules ship with th… |

## Folded from later runs

Three tools an agent wrote in a run after the use cases, each made general
before it came in: the parameters say what the run's copy assumed, and
nothing of that case (its image, offsets, names or wording) is left in the
script. "Written by" is the run.

- `ledger_timeline` — made with `make_tool` in run `se5fdcd` (seat
  `se5fdcd05`) to render one case's events, with that case's title and
  closing paragraph and one password pattern written into the script, and
  its output held under `work/`. Now it reads any run's
  `ledger/entries.jsonl` (or the one named), with `attestations.jsonl` and
  `disputes.jsonl` beside it; `kinds`, `since`, `until`, `match`,
  `exclude`, `keep_duplicates` (entries marked `rel` duplicates) and
  `include_superseded` choose what it keeps, and every entry it leaves out
  is counted by why. An entry marked `sensitive` is withheld by default and
  `redact` takes the patterns; the title, a note, the columns and the format
  (Markdown, CSV, JSON Lines) are the caller's; the E-n links are worked out
  from where the output is; and it writes nowhere under `ledger/`, `tools/`
  or `inputs/`.
- `contact_sheet` — a job command in run `s10d40e` (job `j000558`, seat
  `s10d40e00`) that read one archive's images by the byte offsets of an
  earlier job's member list, tiled them twenty by twenty and grouped the
  counts by that case's app directories. Now the images come from a
  directory, a list, a list file or a tar read in place with `tarfile`;
  tile size, columns, rows, the label (a format over the file's number,
  name, path, hash, size and dimensions) and dedup (sha256, an average hash,
  or none) are parameters; the counts are by parent directory; a manifest
  row is kept for every file and the whole label in the index; and a large
  set is done over several calls within the tool timeout, each carrying on
  where the last stopped.
- `nested_vdi` — a job command in run `sae6e7d` (job `j000136`, seat
  `sae6e7d01`) that mounted one E01 with `ewfmount`, read a deleted
  VirtualBox disk through data runs taken from another job's output, and
  listed the root of each guest file system, with the partition offset and
  the cluster size written in. Now the image (E01 through pyewf, or raw),
  the volume `offset`, `cluster_size`, the runs (inline, or a JSON or text
  file) and `vdi_offset` are parameters, and a VDI that is contiguous needs
  no runs; nothing is mounted and nothing is written out on the way. The
  header is checked by its signature and version, a differencing image is
  refused, blocks stored past the runs given are counted, and it lists
  (paged, recursive), extracts one file, or reads guest bytes, where the job
  only listed a root.

## Candidates kept out of Community

The `$LogFile` scanner and the mapping-pairs decoder written in run
`sae6e7d` (jobs `j000117`, `j000119`, `j000122` and `j000125`; the last
one's output gave the job behind `nested_vdi` its runs) would fold the same
way. They are not here: `$LogFile` parsing is on the paid tier's list in
[docs/community-waves.md](../docs/community-waves.md#what-genuinely-belongs-to-a-paid-tier).
`nested_vdi` takes runs from whatever produced them.
