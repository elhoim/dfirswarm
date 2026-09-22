---
id: documents/macros
title: Documents, macros and embedded objects
when: The sample is an Office document, a PDF, an archive or an email attachment.
needs: [triage/quarantine]
tools: [file_type, doc_probe]
requires_host: [olevba]
---

A document is a container, and the question is what is inside it and what runs
on its own.

**The two Office formats behave differently.** The old one (`.doc`, `.xls`) is
an OLE compound file — a little file system, with the macro project in one of
its streams. The new one (`.docx`, `.xlsm`) is a ZIP: unzip it and read the XML,
and a macro-enabled file has a `vbaProject.bin` inside, which is an OLE compound
file again.

**`.docx` cannot carry a macro and `.docm` can.** A file named `.docx` that
holds a `vbaProject.bin` has been renamed, and that is itself worth reporting.

`doc_probe` says which container it is, lists the parts, and flags the ones that
carry code or an external reference. `olevba` then extracts and deobfuscates the
macro itself and marks which subroutines run automatically — `AutoOpen`,
`Document_Open`, `Workbook_Open` — because a macro that does not auto-run needs
a user to click, and that changes the story.

Beyond macros:

- **External relationships.** A `.docx` can reference a remote template or an
  OLE object by URL, so the file fetches something when opened with no macro at
  all. The reference is in the relationship XML.
- **Embedded objects.** A packager object holding an executable, an LNK, or a
  script, which the user is invited to double-click.
- **RTF** has no ZIP and no OLE container: objects are hex-encoded inline, and
  the exploit history here is mostly equation-editor objects.
- **PDF**: `/OpenAction` and `/AA` run on open, `/JavaScript` carries the code,
  `/Launch` starts a program, and an embedded file stream carries a payload.
  Object streams hide all of the above from a plain `strings`.

Never open any of them in the application that made them. Everything above is a
parse of the bytes.
