---
id: reporting/citations
title: Every claim cites something a reviewer can re-run
when: Whenever you write into the report or sign one off.
needs: [timeline/build]
tools: []
requires_host: []
---

A claim in the report carries one of: a path with an inode, a registry key with
its last-write time, an event record id with its channel, an offset in a blob, a
hash, or the command that produced it. A sentence with none of those is an
opinion and a reviewer will treat it as one.

Answer the question that was asked, under the heading the goal named. The
finish line greps for those headings; more than that, a reader comparing two
runs needs the same shape both times.

Say what you could not establish. A report that answers six of eight questions
and names the two it could not survives review. One that fills all eight with
guesses does not.

Separate what you observed from what you infer. "The service was created at
21:19:22 by record 975 in System.evtx" is an observation. "The dropper installed
it" is an inference, and it needs the chain that gets you there.

Do not cite the catalogue for something you did not open. The listing says a
file exists; it does not say what is in it.
