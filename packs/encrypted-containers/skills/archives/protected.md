---
id: archives/protected
title: Archives and documents with a password
when: A file inside the evidence will not open without one.
needs: [identify/headers]
tools: [archive_probe, file_type]
requires_host: [john]
---

`archive_probe` says what kind of protection a container carries, because the
differences decide what is possible.

**ZIP has two schemes and they are not comparable.** Legacy ZipCrypto is weak
and, where you have a known-plaintext file from the same archive, breakable
outright. AES-256, which modern tools default to, is not. The archive says which
it used, per entry.

**Whether the file names are encrypted matters as much as the data.** A
standard ZIP or 7-Zip archive leaves the central directory readable, so the list
of file names, their sizes and their timestamps are available with no password
at all — and a list of names is frequently the answer to a question about
exfiltration. 7-Zip's header encryption hides that too, and the output says
which you are looking at.

**RAR5 leaves a per-file check value**; RAR3 leaves a different one. Both are
enough to verify a password without extracting.

**Office documents**: the modern format is an OLE container holding an
`EncryptionInfo` stream that names the algorithm and the key derivation. The
2007-era scheme and the 2013-and-later one differ by orders of magnitude in
cost. An older `.doc` may use the 40-bit RC4 scheme, which is trivially
breakable.

**PDF has two passwords.** The user password opens it; the owner password
restricts printing and copying. A PDF with an **empty user password and only an
owner password set** is not encrypted in any useful sense — it opens without
anything and the restriction is advisory. Check that before reporting a
protected document.

Where a password attempt is authorised, the `*2john` helpers turn a header into
a hash and `john` does the work. Get that authorisation in writing, record it,
and put the wordlist and rules you used in the report so the attempt is
reproducible — including when it failed.
