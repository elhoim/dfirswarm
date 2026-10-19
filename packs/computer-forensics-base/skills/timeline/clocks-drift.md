---
id: timeline/clocks-drift
title: Clock changes, drift and NTFS time sets
when: Clocks may be set or drift, or NTFS times disagree.
needs: []
tools: []
requires_host: []
---

Use only if `timeline/clocks` sends you here: a clock may have been set or may drift, or the $STANDARD_INFORMATION and $FILE_NAME times differ. Not for epochs, zones and resolution (`timeline/clocks`).

**Clocks drift and are changed.**
- A logged clock change is a finding; no record of one does not show a steady clock. Correlate independent clocks and carry the offset or drift as an uncertainty.
- Monotonic time orders events inside the sequence it is defined for (a boot, a journal instance, a retained USN or `$LogFile` range). Do not merge unrelated sequences, and across boots and hosts anchor on independent sources.
- NTFS `$STANDARD_INFORMATION` and `$FILE_NAME` times are two sets of observations, each changeable by different means. When they disagree, say so and trust neither as a clock. A creation later than modification is a lead (copying, extraction, restoration and ordinary file system behaviour explain it).

**Record.** The clock change or drift found, the sources correlated and the offset carried as an uncertainty, the sequence a monotonic order holds for, and what would disprove it.

**Does not show.** That a clock was steady because no change was logged, that two clocks agree, or that an order across boots or hosts is causal.
