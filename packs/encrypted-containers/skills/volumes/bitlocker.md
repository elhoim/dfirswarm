---
id: volumes/bitlocker
title: BitLocker, and the protector that needs no secret
when: A Windows volume identifies as BitLocker.
needs: [identify/headers]
tools: [crypto_id, recovery_key_scan]
requires_host: [bdeinfo, dislocker]
---

BitLocker encrypts the volume with a full-volume encryption key, and then
encrypts *that* key once per **protector**. Every protector is a separate way in,
and `bdeinfo` lists all of them before you have any secret at all.

    clear key              no secret required: the key is on the volume
    TPM                    needs that machine's chip; useless from an image
    TPM and PIN            the same, plus something a person knows
    recovery password      the 48 digits, in eight groups of six
    startup key            a .BEK file, usually on a USB stick
    password               a user password
    Active Directory       the recovery password is escrowed in the domain

**A clear key means the volume is effectively unlocked.** Windows creates one
while encryption is suspended — during a firmware update, a servicing operation,
or because somebody ran `manage-bde -protectors -disable` — and forgot to turn
protection back on. `dislocker -V part.img -c -- work/bde/` opens it with
nothing. Check for it first, every time: it has decided cases in four commands.

**A recovery password protector tells you what to look for.** The 48 digits are
often printed, escrowed in Active Directory, saved to a Microsoft account, or
sitting in a text file on another volume in the same case. `recovery_key_scan`
sweeps a tree or a blob for the format. So does a search of the user's OneDrive
folder, their mail, and any USB stick in the exhibit list.

Once you have a key, unlock to a **file**, never in place:

    dislocker -V part.img -p<48-digits> -- work/bde/     # yields dislocker-file
    fls -r work/bde/dislocker-file                        # then it is just a volume

`bdemount` does the same job through libbde. Either way, hash the unlocked
image before you work on it and record which protector you used — a reviewer
will ask how you got in, and "a clear key was present" and "the recovery
password was recovered from the domain" are very different answers.

**BitLocker To Go** is the same scheme on removable media, and it leaves a
discovery volume with a plain FAT header so that an old Windows can show a
"here is how to unlock this" file. That header is why a stick can look
unencrypted at first glance.
