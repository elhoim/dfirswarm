---
id: keys/where-they-hide
title: Where the key already is
when: You need to open something and are about to attack it.
needs: [identify/headers]
tools: [recovery_key_scan, ioc_scan]
requires_host: []
---

Almost every container opened in a real case was opened with a key that was
already in the evidence. Attacking the cryptography is the last resort and
usually the wrong one.

Look here, roughly in order of how often it works:

**Somewhere else on the same machine.** A text file, a note, a spreadsheet, a
screenshot of a recovery key. `recovery_key_scan` sweeps a tree for the
BitLocker 48-digit format and for the shapes a key file takes; an ordinary
keyword search finds the rest.

**The browser's saved passwords.** Chromium's `Login Data` and Firefox's
`logins.json` with `key4.db`. Where the operating system user is known, these
are ordinarily recoverable, and people reuse a volume password.

**A password manager's own database**, which pushes the problem back one step
but often to a password the case already has.

**Memory, and the page file.** A volume that was mounted when the machine was
imaged has its key in memory. So does an archive that was open. This is why
`acquire/images` in the memory pack insists memory is taken first, and why
`pagefile.sys` and `hiberfil.sys` are worth sweeping even on a cold case.

**The domain or the fleet manager.** BitLocker recovery passwords escrow to
Active Directory or Entra; FileVault to an institutional key or to an MDM.
Asking the organisation is a one-line email that saves a week.

**The user's own cloud account**, where they saved the key at enrolment.

**Shell history, scripts and configuration.** A password passed on a command
line is in `~/.bash_history`; one in a backup script is in the script.

Two rules. **Record where a key came from**, because the report must say how you
got in. And **do not put the key itself in the report** — cite where it was
found and record its hash in the ledger, and hand the value over through the
channel the operator named.
