---
id: logs/hunting
title: Hunting with rules, and what a detection is worth
when: The first pass found nothing, or the logs are too large to read by event id.
needs: [logs/security]
tools: [sigma_hunt, evtx_query]
requires_host: [zircolite]
---

Querying by event id answers a question you already knew to ask. A ruleset
answers the ones you did not: several thousand community rules, each one a
pattern somebody saw in a real intrusion, run over every record in the channel.

    sigma_hunt  path=work/extracted/winevt  min_level=high  out_dir=work/hunt

**A detection is a hypothesis with a name, not a finding.** The rule says "this
record looks like technique X". The evidence is the record: take its record id
and channel to `evtx_query`, read it whole, and cite that. A report that quotes
a rule title instead of a record has cited the tool's opinion.

**Community rules are tuned for live estates and this is a forensic image.** An
administrator doing their job trips a dozen. Expect false positives, say how
many you dismissed and why, and never present a count of detections as a measure
of anything.

**Start at high and critical, then widen.** Medium and below is where the noise
lives. If high and critical are empty on a machine you believe was compromised,
that is worth a sentence: either the technique is not in the ruleset, or the
channel that would have caught it was off. Check which with `logs/security`.

**Absence of rules is not absence of logs.** The engines only see the channels
you give them. Sysmon, PowerShell/Operational and the TerminalServices channels
carry most of what modern rules look for, and a machine without Sysmon will
never fire a Sysmon rule no matter what happened on it. Say which channels you
swept.

Neither engine ships with this pack; both are invoked as executables. When the
host has neither, `sigma_hunt` says so, and the honest report line is that no
rule-based sweep was performed — not that nothing was found.

The other half of this is `logs/recovery`: rules can only match records that
still exist. On a machine where the log was cleared, carve the chunks first and
hunt afterwards.
