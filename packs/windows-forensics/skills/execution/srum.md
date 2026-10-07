---
id: execution/srum
title: SRUM resource accounting and network-use limits
when: You need to interpret application resource records, byte counts and their aggregation and attribution limits.
needs: [execution/overview]
tools: [esedb_query]
requires_host: [esedbexport]
---

`C:\Windows\System32\sru\SRUDB.dat` is an ESE database that holds several
resource-accounting tables with different schemas and interval semantics. Collect it
with the ESE log and checkpoint files in the same directory, keep the original set
untouched, and do any recovery on a derivative that you record.

**Reading it.** `esedb_query` runs `esedbexport` and returns the tables as text: with
no `table` it lists them; with one it returns the rows, each numbered `_row` by its
position in the exported file. It decodes nothing and joins nothing, and it does not
read an ESE log. Read the answer's own accounting first: `status` (`complete`,
`partial`, `failed`), `exporter_exit_status`, `timed_out`, `exporter_version`,
`db_sha256`, and the files named under `export_dir`, which hold the exporter's whole
output. A `partial` export lists its tables as `tables_in_partial_export`: a table
missing from it, or short, is not absent from the database. Cite the export by its
manifest, not by a count you remember.

**Joins are yours, and the pack has no reader for them.** An application or user
column is an id into the database's id-map table (`SruDbIdMapTable`); resolve it
there, and do not guess from the table you started in. The mapping's blob cells come
back as the exporter wrote them: decode them offline, read only, and state how.
Record for each figure you cite: table, `_row`, the raw time cell, application id and
resolved name, SID, interface or network-profile id, the unit and what the counter
means in that table. Interface and profile ids need the matching table or a system
artefact (`registry/overview`) before they name a network.

**What it shows.** Resource use the system accounted to an application and a user
context in an interval: byte counters, CPU and similar figures. Each table has its own
interval and its own meaning for a time cell; the exporter's text form of a time and
its zone are what the exporter printed, so keep the raw cell and establish the clock
from the schema before you convert. Do not average, sum or compare across tables
without saying which counters you are adding.

**Bytes are not exfiltration.** A byte counter does not give the remote endpoint, the
content, the process instance, or whether anything left the
organisation. "The application was accounted N bytes sent on interface X in this
interval" is the claim; "data was exfiltrated" is a conclusion that needs named
corroboration: network or proxy records, firewall logs, process-creation records,
file-access evidence.

**Retention and gaps.** Do not assume a retention period or a write cadence. Take the
retained interval from each table (its earliest and latest time) and say it. Delayed
commits, configuration, shutdown, database maintenance and the acquisition time can all
leave gaps near the end or inside the interval. An unreadable database, an unresolved
mapping or a missing recent row is not zero activity.

**Sensitive output.** Application paths and SIDs are in a SRUM export, and a WebCache
export holds URLs that can carry a token: run `esedb_query` as a job with
`secret_output: true` where the case may, and write the location, kind and length of
such a value, never the value, a fragment of it or a hash of it.

`WebCacheV01.dat` and `spartan.edb` are ESE databases too, and `esedb_query` exports
their tables the same way; it resolves no WebCache container to a browser, so read
`browser/artefacts` for what those tables mean.

**Absence is bounded.** "No SRUM row for <application> was found in <tables>,
<retained interval>, <export status>."

**Does not show.** Who used the machine, what data moved or where it went, that a
program ran to completion, which process instance produced a row, or that a program
without a row did not run.
