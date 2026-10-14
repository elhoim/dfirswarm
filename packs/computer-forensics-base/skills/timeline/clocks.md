---
id: timeline/clocks
title: Timestamp semantics, zones and clock uncertainty
when: Before a number or a date string becomes a time in the ledger, or two sources disagree on when.
needs: []
tools: [timestamp_decode]
requires_host: []
---

Use when you turn a stored value into a time, convert a zone, or order events across clocks. Not for choosing parsers for a machine timeline (`timeline/super`) or for an artefact's field layout (the artefact's own skill).

**Keep, per timestamp:** the raw value, the field name, its encoding, epoch, unit and resolution, its zone semantics (UTC, a fixed offset, local time of an unknown zone, none), the source and locator, and what event the field describes (a file's modification is not a person's action). Convert last; keep the raw value beside the result.

**Epoch.** The artefact's schema decides which clock wrote a number, never the reading that looks plausible. `timestamp_decode` lists what the number would be under each epoch in common use (Unix in four resolutions, FILETIME, WebKit, Apple, HFS+, OLE, DOS), exactly: fractions are kept to the nanosecond, the rest is `remainder_s`. It applies no zone or daylight-saving rule; DOS and OLE readings carry no zone. The plausible range is a ranking aid, not evidence: for an old, sentinel or unusual value keep every reading (the default) and decide from the schema.

**Zone.**
- UTC, offset-bearing and local-without-zone are three kinds of value. Do not convert a value already in UTC.
- A local time needs the zone and its rule on the event's date, daylight saving included. A present-day setting is not proof of a past one, and one host setting does not fit every source.
- Find the zone where the artefact family keeps it (the registry on Windows; configuration and `/etc/localtime` on Linux) and record where.
- In a repeated or skipped local hour (a daylight-saving change) the local time is ambiguous or does not exist: keep both readings until another source chooses.
- A stamp with no year (traditional syslog) needs a year basis: record the text, the basis and the zone applied.
- When UTC cannot be established, record the observation and the limit, not a UTC time you lack.

**Resolution and order.** Seconds (syslog), 2 seconds (DOS), 100 ns (FILETIME), a whole day (a date-only record). Invent no order inside a resolution: sort equal times by a fixed rule and say which.

**Clocks drift and are changed.**
- A logged clock change is a finding; no record of one does not show a steady clock. Correlate independent clock sources and carry the offset or drift as an uncertainty.
- Monotonic time orders events inside the sequence it is defined for (a boot, a journal instance, a retained USN or `$LogFile` range). Do not merge unrelated sequences, and across boots and hosts anchor on independent sources.
- NTFS `$STANDARD_INFORMATION` and `$FILE_NAME` times are two sets of observations, each changeable by different means. When they disagree, say so; trust neither as a clock. A creation later than modification is a lead (copying explains it).

**Record.** The zone and its source, the year basis, the epoch and why the schema says so, the uncertainty, what would disprove the reading.

**Does not show.** A timestamp shows what a clock the artefact trusted wrote into that field, not when a person acted, that two clocks agree, or that a time order is causal.
