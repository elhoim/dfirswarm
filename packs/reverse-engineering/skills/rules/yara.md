---
id: rules/yara
title: Rules, and writing one that will still be right next month
when: You have a sample and need to find its family, or find it again elsewhere.
needs: [capabilities/mapping]
tools: [pe_info]
requires_host: [yara]
---

Two directions, and they are different jobs.

**Matching against rules you were given.** Run the set, quote the rule name and
the offset of the match, and treat a hit as a lead. Public rule sets are broad
and a match on a packer or a common library says nothing about the sample's
purpose. Say how many rules were run and from where, so a reviewer can repeat
it.

**Writing a rule for what you found.** This is the part that goes wrong. A rule
built from whatever `strings` printed will match one build of one sample and
nothing else, and it will quietly stop matching when the operator recompiles.

Anchor a rule on things the author cannot change cheaply:

- a mutex name, a named pipe, a registry key or a user-agent the code builds,
- a decryption routine's constant table, or an unusual sequence of instructions,
- the Rich header, which survives a rename and most repacking,
- a resource, an icon or a certificate serial,
- section names and sizes in combination, where they are unusual.

And avoid things that change for free: the file name, the compile timestamp,
absolute addresses, and any string that came from a library rather than from the
author's own code.

Three habits:

1. **Test for false positives before you publish it.** Run the rule over a
   directory of ordinary system binaries. A rule that fires on `kernel32.dll` is
   worse than no rule.
2. **Name the condition after what it identifies**, and put the sample's hash in
   the rule's metadata. A year later nobody will remember why the rule exists.
3. **Say in the report what the rule was built from.** "Matched a rule written
   from this sample" is circular; "matched a rule written from sample A, which
   also matches sample B recovered from the second host" is evidence.
