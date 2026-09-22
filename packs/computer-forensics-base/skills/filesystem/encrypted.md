---
id: filesystem/encrypted
title: A volume the toolkit cannot read
when: fsstat refuses a partition, or the listing is one file you cannot open.
needs: [evidence/imaging]
tools: []
requires_host: [luksdeinfo, fvdeinfo]
---

Tell the three cases apart before you spend anything. They look identical from
`fsstat` and they need entirely different work.

**Encrypted at the volume.** The partition is full-disk encryption: BitLocker,
LUKS, FileVault, VeraCrypt. Identify it from the header rather than guessing.

    BitLocker   "-FVE-FS-" at offset 3 of the volume
    LUKS        "LUKS\xba\xbe" at offset 0
    FileVault   an Apple Core Storage or APFS container with an encrypted volume
    VeraCrypt   no signature at all, which is itself the tell

Metadata first. `bdeinfo` on a BitLocker volume prints the encryption method and
every key protector present: a recovery password, a TPM, a startup key, a
clear key. **A clear key means the volume is effectively unlocked** and
`dislocker` will open it with no secret at all, which has decided more than one
case in four commands. A recovery password protector tells you what to go and
look for: the 48-digit key is often in a printout, in Active Directory, in the
user's OneDrive, or in a text file on another volume in the same case.

Once you have a key, unlock to a *file*, never in place:

    dislocker -V part.img -c -- work/bde/                    # a clear key: no secret needed
    dislocker -V part.img -p<recovery-key> -- work/bde/      # yields dislocker-file
    fls -r work/bde/dislocker-file                           # then treat it as a volume

LUKS is the same shape with `cryptsetup luksDump`, or `luksdeinfo` where the
host has libluksde, for the header and the key slots. An empty key slot count is
the same finding as a missing protector. FileVault answers to `fvdeinfo`, which
prints the encryption method and the key material references without unlocking
anything.

**Encrypted at the file.** The volume reads fine and individual files do not:
office documents, archives, containers. That is an ordinary extract plus a
different question, and the answer is usually elsewhere in the case: a password
in a browser's saved logins, in a note, in shell history, in a memory image.

**Not encrypted at all, just unreadable.** A logical volume manager, a damaged
partition table, a sparse or truncated image, or an offset that is wrong. Rule
this out first, with `evidence/imaging`, because it is the cheapest to fix and
the most common.

Whatever you find, write it down as a finding rather than as an obstacle. "The
second volume is BitLocker with a recovery-password protector and no clear key;
without the key its contents cannot be examined" is a complete, defensible
answer to a question about that volume. Silence is not.
