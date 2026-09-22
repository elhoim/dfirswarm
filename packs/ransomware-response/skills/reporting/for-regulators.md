---
id: reporting/for-regulators
title: The report a regulator, an insurer and a negotiator will each ask for
when: Writing up a ransomware case.
needs: [reporting/citations]
tools: []
requires_host: []
---

Three readers, one report, and each wants something the others do not. Write it
so that all three can find their part without reading the whole thing.

**The regulator wants to know whether personal data left**, when it left, whose
it was, and when the organisation knew. Notification clocks start at awareness,
so the report must state when each fact was established, not only what it is.
This is why `exfil/before-encryption` is the first substantive question and not
the last.

**The insurer wants scope, cost and cause**: how many machines, what was
destroyed as distinct from encrypted, how the operator got in, and whether the
controls the policy assumed were actually in place. Answer that last one
honestly. Multi-factor that was configured but exempted for a legacy protocol is
not multi-factor, and the report saying so is better than the insurer finding it.

**The negotiator, if there is one, wants** the victim identifier from the note,
the family and affiliate, what the operator can prove they hold, and the
organisation's real recovery position — because that is what the decision turns
on.

Four things that must be in it whoever reads it:

1. **What was established, and what was not**, separately. Three positions on
   exfiltration, not two: evidenced; not evidenced with the logging present;
   not evidenced with the logging absent.
2. **A timeline in UTC** from the earliest artefact, not from the encryption.
   Dwell time is usually weeks, and the encryption is the last event.
3. **Whether the operator may still have access**, stated as a position with
   reasons. Encryption is the end of an intrusion's visible part, not of the
   intrusion.
4. **What evidence was lost to the response itself**, and when. Machines rebuilt
   before imaging, logs rolled, shadow copies removed during restoration. A
   reviewer will ask, and the honest answer protects the work.

Keep the ransom note's contents, the wallet addresses and the victim identifier
in an appendix rather than the body. Do not put any recovered credential in the
report at all: cite where it was and record its hash.
