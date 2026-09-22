---
id: scope/first-hour
title: The first hour, and the order it has to be done in
when: A ransomware case starts.
needs: [evidence/verify]
tools: [encrypted_survey, ransom_note_scan]
requires_host: []
---

A ransomware case is not one investigation. It is four, and running them in the
wrong order costs the answer to the most expensive one.

1. **Scope.** How many machines, which, and what proportion of each is
   encrypted. `encrypted_survey` walks a tree and reports the extension change,
   the entropy and the header of each file, and — the part that matters — the
   **clustering of modification times**, which brackets when the encryption ran
   on that machine.
2. **Exfiltration, before anything else is touched.** This is the question that
   decides the regulatory position and the negotiation, it is answered from
   evidence that ages fastest, and it is the one most often started last. See
   `exfil/before-encryption`.
3. **Entry and spread**, which is an ordinary intrusion investigation. The
   Windows, Linux and network packs do this work; this pack does not repeat
   them.
4. **The encryptor itself**, which is usually the least valuable of the four.
   Knowing the family is useful for a decryptor and for attribution; it rarely
   changes what the organisation must do.

**Preserve before you restore.** Every hour of restoration destroys evidence:
shadow copies go, event logs roll, systems are rebuilt. Get images or triage
collections of the first machines encrypted, the domain controller, and
anything with outbound traffic in the window, before the restoration programme
starts. If you win one argument in the first hour, win this one.

**The first machine encrypted is not the first machine compromised.** Dwell time
before deployment is usually weeks. Bracket the incident from the earliest
artefact you can find, not from the encryption.

**Do not assume the operator has left.** Encryption is the last step of an
intrusion, not the end of one. Treat credentials, remote access and persistence
as live until proven otherwise, and say so in the report.
