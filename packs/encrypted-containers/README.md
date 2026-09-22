# Encrypted Containers Pack

Telling one kind of encryption from another before anybody spends an hour on it,
and finding the key that is already in the evidence.

Depends on the Computer Forensics Base Pack, whose `filesystem/encrypted` skill
covers the three reasons a volume will not open. This pack is what to do once
you know it is the encrypted one.

## What it carries

**Five skills**: `identify/headers`, `volumes/bitlocker`,
`volumes/luks-filevault`, `archives/protected`, `keys/where-they-hide`.

**Three tools.** `crypto_id` names the scheme from the header and reads a LUKS1
key slot table without any key — the enabled slot count is a finding on its own.
`archive_probe` says whether a container is protected, with which scheme, and
whether the **file names** are readable anyway, which is often the whole answer
to an exfiltration question. `recovery_key_scan` sweeps a tree for the
BitLocker 48-digit format, private keys and the files people save a recovery key
in — and returns a shape and a hash rather than the value.

**One goal template**: `what-is-locked.md`.

## Three things the skills insist on

**Check for a clear key first.** A BitLocker volume with one opens with no
secret at all, and it exists more often than people expect: Windows creates one
while encryption is suspended and forgets to turn protection back on.

**The key is usually already in the evidence.** A text file, a browser's saved
passwords, memory, the page file, the domain, the fleet manager. Attacking the
cryptography is the last resort and usually the wrong one.

**Do not start an attack you have not been asked for.** It may be outside the
authority the engagement gives you, and where the material is a third party's it
may be unlawful. Establish what the container is, report it, and ask.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/encrypted-containers
    scripts/swarm.sh start --pack computer-forensics-base,encrypted-containers ...
