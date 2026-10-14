---
id: documents/pdf-rtf
title: PDF and RTF structure: objects, actions, embedded content
when: A PDF or RTF must be read for its objects, actions, embedded files or OLE objects.
needs: [triage/quarantine]
tools: [doc_structure, file_type]
requires_host: []
---

Use when the sample is a PDF or RTF and the question is what it contains. Not for opening it in a reader, contacting a target, or deciding that anything ran.

Run `doc_structure` in a job. Read `status`, `problems`, `limits_hit` and `coverage` before any field: a budget reached or an unreadable object is a gap, not an absence.

**PDF**
1. `structure_source` says whether the cross-reference chain was used or the file was rebuilt by scanning for object headers (`anomalies` says why). `revisions` lists each update; `objects_scan.numbers_defined_more_than_once` and `headers_not_in_the_cross_reference_chain` show content a reader following the newest chain does not use. That content is in the file: read it as data, with its object numbers.
2. `encryption_summary`: `found` true means the current trailer names an encryption dictionary, read in `encryption.dictionary` (handler, `v`, `r`, crypt-filter methods, permission flags; verifiers by length only). Stream and string content is then encrypted and this tool does not decrypt it, so actions inside are unseen. `found` null is not determined; false is bounded to the chain read. Permission flags ask a reader to restrict; they protect nothing.
3. Actions (`actions`, table `pdf_actions`): an action, the key that reaches it (`trigger`) and whether anything reaches it (`reached_from_catalog`) are three facts. A destination is not an action. Whether a reader runs an action depends on the reader, its version and settings. For JavaScript, `script` gives the form and size; write scripts with `extract: ["javascript"]` and read them as text, never run them. `Launch` shows lengths of its parameter strings, `URI` a redacted target (the whole only with `write_values`).
4. Embedded files (`embedded_files`): stream object, size and filters. Write one with `pdf:<n>` (filters undone) or `pdf-raw:<n>` (as stored), hash it, and route it by `file_type`; its parent object is part of the record.
5. `streams.undecodable_filter` counts streams behind filters this tool does not decode (LZW, JBIG2, JPX and others): contents unread. `pages` gives the declared `/Count` and the leaves traversed: neither is a verified page count.

**RTF**
6. `structure` (open groups, stray braces, bytes after the last group) and `objects`: kind, class, data length in hex digits and the decoded OLE 1.0 header; a payload that is a compound file is read in `nested_compound_file` (VBA, encryption). `fields` and `templates` give a field's first word and a target's length; the whole is in the values file. A `\bin` block is skipped by its declared length.

Sensitive output: scripts, targets and embedded files can hold credentials. Run these jobs with `secret_output: true`; cite object, finding id and length.

Shows: structure, actions with their triggers, embedded content locations. Does not show: that an action ran, a fetch happened, what encrypted content holds. Record: `doc_structure` status, problems, `structure_source`, revisions, object numbers, extracted files.
