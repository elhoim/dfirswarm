---
id: filesystem/extract
title: Get a file out of an image, and prove which file it was
when: You need the bytes of something the listing names.
needs: [evidence/catalog]
tools: [icat_extract, sig_carve]
requires_host: [icat, fls, istat]
---

Work by inode, not by path. A path is ambiguous across deleted entries and
reused records; an inode with its attribute id is not.

Every command below needs the volume's offset **in sectors**. Get it once from
`evidence/imaging` rather than guessing it per command.

    fls -r -o <offset> image.E01 | grep -i <name>      # find the entry
    istat -o <offset> image.E01 <inode>                # confirm size, times, allocation
    icat -o <offset> image.E01 <inode> > work/extracted/<you>/<name>

Then hash what you wrote and put the hash in the ledger with the inode. An
extract nobody can tie back to a record is worthless.

Claim the destination path before you redirect into it. A shell redirect into a
path a peer holds is reported as a collision against your name.

The trap that costs the most: a deleted entry whose clusters have been reused.
`icat` returns whatever is there now, which may be another file entirely. Check
the allocation status in `istat`, and check that what came out has the header you
expected. If a carved PE does not start `MZ`, you have someone else's bytes.

Nothing you extract can execute. The extraction directory is held no-exec by the
kernel. That is deliberate: read it, parse it, hash it, never run it.
