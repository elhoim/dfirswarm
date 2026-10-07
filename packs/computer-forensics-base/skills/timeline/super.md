---
id: timeline/super
title: Build and validate a scoped machine timeline
when: Broad parser output can identify relevant events or improve source coverage.
needs: [timeline/build]
tools: [timeline_super, catalog_search]
requires_host: [log2timeline, psort]
---

Two timelines, two jobs. The ledger is yours: facts you decided were worth
recording, each cited and defensible. A super timeline is the machine's: what the
parsers that were enabled produced from the sources they could read. It is not
every timestamp on the volume. Which parsers ran, which sources could not be read
and what failed decide what is in it, so keep the scope, the parser selection, the
inaccessible sources and the errors with it, and never present it as the first.

Run `timeline_super` as a job with the source objects declared and a new directory:

    timeline_super  source=inputs/disk.E01  out_dir=work/timeline  parsers="<names>"

**Name the parsers.** A default run over a large image takes hours and returns
tens of millions of events, mostly file metadata. Read the installed Plaso's help
and parser inventory (`log2timeline` and `psort` print them) before choosing a
filter: names and presets vary by version, so take none from memory. Start with
the parsers the question needs, document the gaps this leaves, and widen when
another source family could change the answer. File metadata events are useful
where their meaning bears on the question; the size of a volume alone does not
predict how long a run takes.

**Give it the timezone** when the machine's is known (`timezone`), and say which
you used: several formats store local time and Plaso needs the machine's zone to
convert them. Derive it with `timeline/build` for each source, not from one host
setting. Without it Plaso used its own default, which the tool does not read back;
the storage file records it. State the zone of any filter and whether its bounds
are inclusive.

**Read the result before you trust it.** `status` is `complete` (both programs
exited 0, wrote their files and every line parsed), `partial` or `failed`;
`collect_exit` and `export_exit` are the programs' own; the versions are what they
print; `invalid_lines` counts output lines that were not events. `complete` means
the pipeline finished, not that every parser read every source: Plaso's own
processing report of the storage file (`pinfo`) says what each parser did, and a
negative should not rest on the timeline before you have read it. Partial output
can support a qualified observation and never an unqualified absence. An existing
output directory is refused, so each run has its own.

**Then narrow before you read.** The storage file stays. To make another export
without collecting the evidence again, call `timeline_super` with `mode: export`,
the `.plaso` as `storage_file` and a `psort_filter`; calling it in the default mode
again collects everything again. Filter syntax is the installed `psort`'s, for
example `date > '2026-02-14 00:00:00' AND date < '2026-02-16 00:00:00'`: check it
against that version's help.

Three habits that separate a useful timeline from a wall of rows:

1. **Find the window first, then work the artefacts.** Bracket the hours that
   matter, then go to the artefact family's own skill for anything you intend to
   claim. For each material event cite the sealed parser output and the artefact's
   own locator, then check what the timestamp means. A row can be cited and is not
   self-validating, and it does not establish an actor or a cause.
2. **Never paste it into the report.** Take the rows that matter into the ledger
   with `record`, each with the artefact it came from. The report cites the ledger.
3. **Say what produced it.** The parser filter, the timezone given, the versions the
   result returns and the exit codes belong beside the timeline, because a second
   examiner cannot reproduce it otherwise.

This pack declares `log2timeline` and `psort`; a declaration does not install them.
Check the worker image's inventory, and when Plaso is missing say so in the report
rather than implying a timeline was built and found nothing. `catalog_search` can
tell you whether a catalogue generation already holds a timeline (`which=timeline`
reads a partition's own timeline, not a Plaso output).
