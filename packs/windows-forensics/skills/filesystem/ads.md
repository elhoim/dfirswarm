---
id: filesystem/ads
title: Alternate data streams, and execution from them
when: Something is hidden, or a listing shows a file whose size does not match its contents.
needs: [filesystem/mft]
tools: [extract_stream, lnk_parse]
requires_host: [fls, icat, istat]
---

A stream is a second `$DATA` attribute with a name. `file.txt:payload.exe` is
one file to the file system and two to an examiner.

They are not hidden from the toolkit. `fls -r` prints them, so grep the
catalogue listing for a colon before you reach for anything cleverer. The
listing is where three of five hidden items were found in the published NTFS
case, inside four minutes.

Extract by inode with the stream's own attribute id, not by path:

    icat -o <offset> image.E01 168-128-4 > work/extracted/<you>/payload

Then hash it and compare it against the visible file it hides behind. A stream
that is byte-identical to a legitimate binary is a copy, not a payload.

Two specific patterns worth knowing:

- A stream on a file named after a reserved DOS device (`LPT1.txt`, `COM1.txt`)
  cannot be opened by ordinary Win32 tools at all. The toolkit does not care.
- Prefetch for a binary launched from a stream is itself written as a stream, on
  a file named after the host, because a colon cannot appear in a file name.
  Two zero-length text files in `C:\Windows\Prefetch` with streams on them are
  direct proof of execution from a stream. Parse them with `prefetch_mam`.

A container can lie about its type. A file called `.jpg` that `file` identifies
as a ZIP is the interesting one.
