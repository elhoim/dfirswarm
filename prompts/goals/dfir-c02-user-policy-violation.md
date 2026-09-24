> From [docs/use-cases/dfir-c02-user-policy-violation](../../docs/use-cases/dfir-c02-user-policy-violation/README.md): the goal document a real run was given,
> and what that run produced is written up beside it. The evidence filenames below are
> the ones that case had — change them, and the checks that name them, for yours.

## Goal

A Windows workstation image prepared for a full Windows forensics course, published as the "User Policy Violation Case". The examiner's brief says the image covers every recent system artifact: file carving and keyword search, NTFS, the SYSTEM/SOFTWARE/SAM/NTUSER.DAT/USRCLASS.DAT hives, LNK files, jump lists, libraries, ShimCache, Windows Search, thumbcaches, prefetch, recycle bins, USB devices, event logs, web and Outlook email, Internet Explorer and Chrome, and Skype. Find the policy violation and prove it.

The evidence is under `inputs/` (read-only; call `inputs` to list it):
`inputs/4orensics.001`, a 26.5 GB raw disk image of a Windows machine (MD5 688cf22a83c290ba55fa08fbce69027d per the published README). `inputs/CASE.md` is the published brief.

### Questions the report has to answer

1. System profile: Windows edition and install date, computer name, time zone, network configuration, every user account with its SID, creation and last logon.
2. What is the policy violation? State the hypothesis and prove it: who did what, when, and the artifacts that show it.
3. Program execution: what was run, by which user, when, and how you know (Prefetch, ShimCache, Amcache, UserAssist, jump lists, LNK files, RunMRU).
4. Files of interest: documents, downloads, deleted and recycled files (recycle bins, $UsnJrnl, carving), thumbcaches and Windows Search entries that show them.
5. USB and removable devices: every device connected, when, under which user, and what was accessed on it (SYSTEM/SOFTWARE/NTUSER, setupapi, event logs, LNK, shellbags).
6. Communications: email (web and Outlook), browsers (Internet Explorer and Chrome: history, searches, downloads, cache), Skype (accounts, contacts, chats, calls, transfers).
7. The timeline of the violation, from first related event to last, across every source.
8. Hypothesis, approach, and anything else the examiner should know.

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

`work/report.md` exists, answers every question under headings `## 1.`, `## 2.`, `## 3.`, `## 4.`, `## 5.`, `## 6.`, `## 7.`, `## 8.`,
every answer cites evidence, the critic has posted a sign-off on the board as a `result`
post that starts a line with `SIGN-OFF:` and names what they verified, `work/timeline.md` holds the merged timeline as a
table with at least 40 dated rows built from the ledger, the ledger holds
the dated events the timeline rests on, and `inputs/` is unchanged.

## Checks

- `test -f work/report.md`
- `for n in 1 2 3 4 5 6 7 8; do grep -q "^## $n\." work/report.md || exit 1; done`
- `test -f work/timeline.md`
- `test "$(grep -c '^| ' work/timeline.md)" -ge 40`
- `test "$(grep -c '"kind":"event"' ledger/entries.jsonl)" -ge 10`
- `awk 'FNR==1{r=0} /^tag: result$/{r=1} r&&/^\**SIGN-OFF/{m=1;exit} END{exit !m}' threads/main/*.md`
- `grep '"tool":"inputs_check"' traces/events.jsonl | tail -1 | grep -q '"content_ok":true'`
  (`inputs_check` is an event the harness writes itself when `done` verifies
  the inputs, before it runs these checks. Nobody needs to forge a tool for
  it, and `make_tool` will refuse that name.)
