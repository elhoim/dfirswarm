---
id: identify/family
title: Identifying the family, and what that is worth
when: You need to name what this is, for a decryptor, a negotiation or attribution.
needs: [scope/first-hour]
tools: [ransom_note_scan, encrypted_survey]
requires_host: [yara]
---

Four independent identifiers, and they should agree before you name anything.

**The note.** `ransom_note_scan` finds the note files across a tree and pulls
out what identifies the group: the onion address, the contact email or portal,
the victim identifier, a wallet address, and the wording itself, which is often
copied verbatim between campaigns of the same family. The victim identifier is
also what a negotiator will need.

**The extension and the file marker.** The appended extension is the obvious
one and the least reliable — it is configurable and affiliates change it. The
**trailing bytes of each encrypted file** are better: many families write a
magic value, a wrapped key or the original size at the end.
`encrypted_survey` reports the tail of a sample of files for this.

**The binary**, where one survived: YARA family rules, and the imports and
strings the reverse engineering pack surfaces.

**The behaviour**: the shape of the deployment, the tools used to spread, the
exclusions, the order of operations. This identifies the *affiliate* rather than
the family, and in a ransomware-as-a-service world the affiliate is more often
the useful unit.

**Be careful what the name buys.** Naming the family does not usually change
what the organisation must do, and it can mislead: a well-known name attracts a
published decryptor that may not work on this variant, and it invites an
assumption about the operator's behaviour that the affiliate may not share.

**Check for a published decryptor**, from law enforcement or a vendor, before
anyone pays anything — and test it on a copy, never on the only remaining copy
of the data. Where the family's implementation is flawed, recovery without a key
is sometimes possible; where it is not, no amount of analysis changes that, and
saying so plainly is part of the job.
