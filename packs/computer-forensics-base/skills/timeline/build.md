---
id: timeline/build
title: Preserve timestamp meaning and uncertainty
when: Before interpreting or combining dated observations.
needs: []
tools: [timeline_super, timestamp_decode]
requires_host: []
---

Use when you record a dated fact or combine dated observations. Not for zone and daylight-saving rules (`timeline/clocks`), clock drift (`timeline/clocks-drift`) or the machine's timeline (`timeline/super`).

Put every dated fact in the ledger with `record` as you find it, not at the end. This is the timeline the report cites, and it is yours: each row is a fact you decided was worth recording, with a citation. The machine's version of the same volume is `timeline/super` (`timeline_super`): it finds the window, and it is not the report's timeline. `kind: event` needs an ISO 8601 UTC timestamp, the source and how to check it, and `clock` says which clock the time came from. The harness renders `ledger/ledger.md`; the report cites that file.

**Preserve before you convert.** For each timestamp keep the raw value, the field name, its encoding, epoch, unit, precision and zone semantics, the source object and record locator, and what event the field actually describes (a file's modification is not an action by a person). Convert by the artefact's schema, after preserving the original. Do not convert a value that is already UTC a second time. When UTC cannot be established, record the observation and the timing limitation, and do not write a UTC time you do not have. Keep intervals and date-only precision, and invent no order between equal or overlapping times. A multi-machine case rests on getting every log into one zone: record each conversion and why. The zone rules in force on the event's date are in `timeline/clocks`; a clock that was changed or drifts, and monotonic order, in `timeline/clocks-drift`.

When a field holds a number and nothing says which clock wrote it, do not guess. `timestamp_decode` lists what the number would be under each epoch in common use, with its fractions: it generates candidates, the artefact's schema picks the clock, and a plausible date is not a determination. Keep the raw value beside any converted time.

Put confidence on a row: what you saw, what it implies, and what would disprove it.

**Does not show.** A timestamp shows what a clock the artefact trusted recorded in that field. It does not show when a person acted, or that two sources' clocks agree.
