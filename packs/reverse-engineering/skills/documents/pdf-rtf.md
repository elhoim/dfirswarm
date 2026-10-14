---
id: documents/pdf-rtf
title: PDF and RTF structure: objects, actions, embedded content
when: A PDF or RTF must be read for its objects, actions, embedded files or OLE objects.
needs: [triage/quarantine]
tools: [doc_structure, file_type]
requires_host: []
---

Use when the sample is a PDF or RTF and the question is what it contains. Not for opening it in a reader, contacting a target, or deciding that anything ran.

Run `doc_structure` in a job; read `status`, `problems`, `limits_hit` and `coverage` first: a budget reached or an unreadable object is a gap, not an absence.

**PDF**
1. `structure_source`: the cross-reference chain, or a rebuild by scanning for headers (`anomalies` says why). `revisions` lists each update; `objects_scan.numbers_defined_more_than_once` and `headers_not_in_the_cross_reference_chain` show content the newest chain does not use: data, cited by object number.
2. `encryption_summary`: `found` true: the current trailer names an encryption dictionary (`encryption.dictionary`: handler, `v`, `r`, crypt filters, permission flags; verifiers by length only). Strings and streams are then ciphertext and no key is tried: actions of objects outside object streams are still listed, each target string marked `ciphertext: true`, by length only; objects in an encrypted object stream are unread (`census.objects_unreadable`). `found` null is not determined; false is bounded to the chain read. Permission flags ask a reader to restrict; they protect nothing.
3. `actions` (table `pdf_actions`): an action, the key that reaches it (`trigger`) and whether anything does (`reached_from_catalog`) are three facts. A destination is not an action; whether a reader runs one depends on the reader, its version and settings. `script` gives form and size; write scripts with `extract: ["javascript"]` and `extract_to` (under `$OUT`) and read them as text, never run them. `Launch` gives string lengths, `URI` a redacted target (whole with `write_values`).
4. `embedded_files`: stream object, size, filters. Write one with `pdf:<n>` (filters undone) or `pdf-raw:<n>` (as stored); its `extracted` row has the `sha256`; route it by `file_type` and record its parent object.
5. `streams.undecodable_filter` counts streams behind filters not decoded here (LZW, JBIG2, JPX): unread. `pages` gives the declared `/Count` and the leaves traversed: neither is a verified page count.

**RTF**
6. `structure` (open groups, stray braces, trailing bytes) and `objects`: kind, class, hex length, the data's `signature` (no byte of it) and the OLE 1.0 header; a compound-file payload is read in `nested_compound_file`. `fields` gives `instruction_word` only for a known field type, and the length; `templates` a withheld target and its length. All are rows of `rtf_fields` and `rtf_templates`, whole in the values file with `write_values`; one past its bound is cut, and a limit. `\bin` data is skipped by its declared length.

Sensitive output: scripts, targets and embedded files can hold credentials: use `secret_output: true` with `extract` or `write_values` (without them targets are withheld); cite object, finding id and length.

Shows: structure, actions with their triggers, where embedded content is. Does not show: that an action ran or a fetch happened, what encrypted content holds. Record: status, problems, `structure_source`, revisions, object numbers, extracted files.
