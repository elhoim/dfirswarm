---
id: timeline/super
title: The machine timeline, and what it is not
when: You need the window an incident happened in, or the evidence is too large to read artefact by artefact.
needs: [timeline/build]
tools: [timeline_super, catalog_search]
requires_host: [log2timeline, psort]
---

Two timelines, two jobs. The ledger is yours: facts you decided were worth
recording, each with a citation, each defensible. A super timeline is the
machine's: every timestamp on the volume, from every parser, with no judgement
applied at all. You want both, and you must never present the second as the
first.

    timeline_super  source=inputs/disk.E01  out_dir=work/timeline
                    parsers="winreg,winevtx,prefetch,lnk,filestat"

**Name the parsers.** A default run over a 60 GB image takes hours and returns
tens of millions of events, and the great majority are `filestat` rows that say
nothing. A named filter turns that into minutes. Start narrow, widen when the
narrow pass points somewhere:

    winreg,winevtx,prefetch,lnk,recycle_bin,usnjrnl   a Windows intrusion
    syslog,utmp,bash,selinux,systemd_journal          a Linux server
    plist,mac_appfirewall_log,macwifi,utmp            a macOS host
    filestat                                          only when you want the file system itself

**Give it the timezone.** Plaso writes UTC, but several formats store local
time and it needs the machine's own zone to convert them. Get it from
`registry/system-profile` on Windows or `/etc/timezone` on Linux, pass it, and
say in the report which zone you used. A wrong zone shifts a whole class of
artefacts and nothing in the output complains.

**Then narrow before you read.** The storage file stays; `psort_filter` cuts it
down without running the collection again:

    "date > '2026-02-14 00:00:00' AND date < '2026-02-16 00:00:00'"

Three habits that separate a useful timeline from a wall of rows:

1. **Find the window first, then work the artefacts.** Use the machine timeline
   to bracket the hours that matter, then go to the artefact family's own skill
   for anything you intend to claim. A Plaso row is a pointer, not a citation.
2. **Never paste it into the report.** Take the rows that matter into the ledger
   with `record`, each with the artefact it came from. The report cites the
   ledger.
3. **Say what produced it.** The parser filter, the timezone and the tool
   version belong beside the timeline, because a second examiner cannot
   reproduce it otherwise. `timeline_super` returns all three.

Plaso is on the host or it is not; this pack does not ship it. When it is
missing, say so in the report rather than implying the timeline was built and
found nothing.
