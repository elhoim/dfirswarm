## Goal

A system used for illegal activity: a user accessed confidential files they were not supposed to access. Two accounts are the suspects, "joker" and "IEUser". Every answer needs proof with details; the workshop's rule is "screenshot or it did not happen", which for this swarm means the command and its output, quoted.

The evidence is under `inputs/` (read-only; call `inputs` to list it):
`inputs/BSidesAmman21.E01`, a 5.3 GB E01 image of the Windows system (extracted from a five-part 7z). `inputs/README.rtf` came with it. `inputs/CASE.md` is the published brief.

### Questions the report has to answer

1. What is the hash value of the given forensic image? (The acquisition record inside the E01, `ewfinfo`, and a hash you compute of the image file itself, stated separately.)
2. Which user account was used to access the confidential documents?
3. Explain in detail what proof supports that answer.
4. Did the user access the confidential files from a local drive or a network location?
5. What proof supports that answer?
6. List every file that was accessed, with full paths.
7. Provide two different kinds of evidence that prove those files were truly accessed.
8. Which application was used to open any of the confidential documents?
9. The image with the text "AnotherPassword4U" in a user home directory: what is the full path to the file(s) of interest?
10. What is the Volume Serial Number of the volume where that file exists?
11. What are the Modified, Accessed and Created (MAC) timestamps of that file, in UTC?
12. DCode.exe was used by one of the users; the workshop warns this is a tricky question. Which user ran it, and what evidence supports that?
13. How many times was DCode.exe used?
14. When was it last used?
15. Where was the application located (full path)?
16. Timeline of the confidential-file access and the DCode.exe activity, plus anything else the examiner should know.

### Ground rules

- `inputs/` is read-only and stays byte-for-byte what it was. Never `cat`
  or `read` an image whole. Work on images in place with The Sleuth Kit
  (`mmls`, `fsstat`, `fls`, `istat`, `icat`, `ifind`, `blkls`, `jls`,
  `tsk_recover`; E01 files are read natively), libewf (`ewfinfo` for the
  acquisition record and hashes), Volatility 3 (`vol`), `regipy` and
  `python-evtx` (Python 3.12), `strings`, `sqlite3`, `exiftool`, `openssl`,
  `gpg`. There is no root: no mounting, no `sudo`.
- If `SWARM.md` has an "Evidence catalog" section, the first pass is already
  done: read `catalog/` (partition table, file list, body file, MAC timeline,
  memory process lists) instead of rebuilding it.
- Extract what you need with `icat`/`tsk_recover` into `work/extracted/`
  (quarantined: nothing there can execute; hash everything you pull out) and
  analyse the extracts. Your own scratch goes under `work/<your id>/`.
- Every dated event you establish goes into the ledger with `record`
  (kind=event, ISO 8601 UTC, source, evidence); indicators as kind=ioc,
  conclusions as kind=finding. The timeline and the report cite
  `ledger/ledger.md`.
- Every claim in the report cites its evidence: the path, the inode, the
  offset, the record id, the registry key, the command that produced it.
  A claim without evidence is a hypothesis and is labelled as one.
- Write every post and file in English. Use tables where they help.
- If a step needs a tool this host does not have, say exactly what is
  missing and what you established up to that point; forge a tool with
  `make_tool` where a small script closes the gap.

## How to divide the work

Seats are assigned in `SWARM.md` (change them on the board if you see a
better split). The critic and editor verifies every citation before it goes
into `work/report.md`, assembles the report from the seats' notes and the
ledger, and posts the sign-off the definition of done requires. The timeline
seat builds `work/timeline.md` from `ledger/ledger.md`. Do not all run the
same command on the same image: read the catalog and the board first.

## Definition of done

`work/report.md` exists, answers every question under headings `## 1.`, `## 2.`, `## 3.`, `## 4.`, `## 5.`, `## 6.`, `## 7.`, `## 8.`, `## 9.`, `## 10.`, `## 11.`, `## 12.`, `## 13.`, `## 14.`, `## 15.`, `## 16.`,
every answer cites evidence, the critic has posted a sign-off on the board
naming what they verified, `work/timeline.md` holds the merged timeline as a
table with at least 30 dated rows built from the ledger, the ledger holds
the dated events the timeline rests on, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 30`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 10`
- `grep -rqi 'sign-off' threads/main/`
- `grep -q '"tool":"inputs_check"' traces/events.jsonl`
- `grep -qi 'AnotherPassword4U' work/report.md`
- `grep -qi 'DCode' work/report.md`
