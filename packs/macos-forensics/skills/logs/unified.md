---
id: logs/unified
title: The unified log
when: You need what happened on this machine, minute by minute, and syslog is empty.
needs: [triage/system-profile]
tools: [unified_log]
requires_host: [log]
---

macOS stopped writing text logs years ago. `/var/log/system.log` is nearly
empty on a modern machine and the real record is the unified log: a compressed
binary format under

    /var/db/diagnostics/            .tracev3 files, the log itself
    /var/db/diagnostics/Persist/    the persisted ring
    /var/db/uuidtext/               the format strings the entries refer to

**Both directories are required.** A `.tracev3` holds references into
`uuidtext`, not the message text, so a collection that took `diagnostics` and
left `uuidtext` behind produces entries whose message is a placeholder. If you
have only one, say so: it is a limit on the evidence, not on the analysis.

Reading it:

    log show --archive <path> --style ndjson --info --debug
    UnifiedLogReader.py, where the examination host is not a Mac

`unified_log` wraps whichever is present. Always pass `--info` and `--debug`:
the default level hides most of what an investigation wants, and the omission is
silent.

**Retention is short and it is not configurable in any useful way.** A busy
machine keeps days, not months. An event three weeks before acquisition is
usually gone, and its absence means nothing at all — say that rather than
implying the machine was quiet.

What it is very good for: process launches with their arguments, TCC prompts and
decisions, network interface and VPN changes, USB attachment, screen lock and
unlock, and every `sudo` and authentication attempt. Filter by `subsystem` and
`process` rather than grepping the whole thing, and quote the subsystem with the
line so a reviewer can re-run the same predicate.
