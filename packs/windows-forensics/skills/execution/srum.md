---
id: execution/srum
title: SRUM, for what a program did on the network
when: You need bytes moved, or a program's activity by the hour.
needs: [execution/overview]
tools: [esedb_query]
requires_host: [esedbexport]
---

`C:\Windows\System32\sru\SRUDB.dat` is an ESE database holding hourly rows per
application: bytes sent and received, the network it was on, CPU time, and the
user SID.

Read it with `esedb_query`, which shells out to `esedbexport` and lists or dumps
tables. The application is an id into `SruDbIdMapTable`; resolve it there rather
than guessing from the table you started in.

It answers two questions nothing else answers well: how much data a process
moved, and which wireless or wired network it moved it over. For an exfiltration
case that is the difference between "a tool ran" and "a tool sent 4 GB".

The retention is typically 30 to 60 days and the writes are hourly, so an event
minutes before acquisition may not be there. Absence near the end of the
timeline means nothing.

`WebCacheV01.dat`, under the user's `AppData\Local\Microsoft\Windows\WebCache`,
is the same database engine and the same tool reads it. That one carries the
browsing history for the legacy browsers.
