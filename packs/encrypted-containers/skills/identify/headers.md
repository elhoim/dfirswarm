---
id: identify/headers
title: Which kind of encryption this is, before spending anything on it
when: A volume, a file or an archive will not open.
needs: [filesystem/encrypted]
tools: [crypto_id, file_type]
requires_host: []
---

Three questions, in order, and the first two are free.

**What is it?** `crypto_id` reads the header. Each scheme leaves a signature
except the one whose whole point is not leaving one:

    BitLocker        "-FVE-FS-" at offset 3 of the volume
    BitLocker To Go  "MSWIN4.1" with an FVE metadata block behind it
    LUKS1            "LUKS\xba\xbe" at offset 0, version 1
    LUKS2            the same magic, version 2, with a JSON metadata area
    FileVault        an Apple Core Storage or APFS volume marked encrypted
    APFS encrypted   the container says so; the volume will not mount
    VeraCrypt        no signature at all, and a size that is a round multiple
    7-Zip, RAR, ZIP  a flag in the archive, not a container of its own
    Office, PDF      an encryption dictionary inside the document

**Can it be opened without a secret?** This is the question worth asking before
any other, and it is answered by metadata alone. A BitLocker volume with a clear
key is effectively unlocked. A LUKS header with one populated slot tells you how
many passwords exist. An Office document with an empty owner password opens
without anything at all.

**If not, where would the key be?** See `keys/where-they-hide`. The answer is
almost never a password attack; it is somewhere else in the same case.

**Do not start an attack you have not been asked for.** Attempting to break
encryption may be outside the authority the engagement gives you, it burns hours
that metadata would have saved, and where the material is a third party's it may
be unlawful. Establish what the container is, report it, and ask.

An unreadable volume is not necessarily encrypted. Rule out a logical volume
manager, a damaged partition table and a wrong offset first — `evidence/imaging`
in the base pack — because those are cheaper to fix and far more common.
