---
id: logs/powershell
title: PowerShell logs, script blocks and interactive history
when: You need to interpret retained PowerShell content, invocation context and logging limits.
needs: [logs/security, filesystem/extract]
tools: [evtx_query, mft_records, regkv]
requires_host: []
mentions: [pwsh]
---

PowerShell leaves several kinds of record, enabled separately, and none is
guaranteed. Inventory what the image holds before you read any of it, and keep
Windows PowerShell (5.x) apart from PowerShell 7 (`pwsh`): they are separate
products, with their own host names and configuration and, where they log to the
event log, their own channel (look for `PowerShellCore/Operational` in the image).

    Microsoft-Windows-PowerShell/Operational
        4104  a script block as the engine compiled it (ScriptBlockText, ScriptBlockId,
              MessageNumber, MessageTotal)
        4103  module and pipeline logging: a command with its bound parameters
        4105/4106  a block's invocation started and stopped, where that setting was on
    Windows PowerShell (the classic log)
        400/403  engine state changed (HostApplication, EngineVersion, HostVersion)
        600  provider started; 800  pipeline details, where module logging was on
    Users\<u>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
    Transcripts, in the place the session or policy named

Whether script block logging, module logging and transcription were on is policy:
read it with `regkv` from the SOFTWARE hive and each NTUSER.DAT (for example under
`Policies\Microsoft\Windows\PowerShell`, keys `ScriptBlockLogging`, `ModuleLogging`,
`Transcription`). Without that, an absent 4104 is a coverage question
(`logs/security`), not evidence that nothing ran. Read the Operational channel with
`evtx_query` for 4104 even when logging was not established: the engine may log
content it considers suspicious regardless of policy. Do not assume that holds for
every build, or survives tampering with the logging.

**Reassembling a long block.** A long script arrives as several 4104 records. The
pack has no assembler: from `result_file` (JSON Lines, whole XML), group rows by
computer, ScriptBlockId and then MessageNumber, and compare the parts you hold with
MessageTotal. Keep the record id and `record_offset` of every part; keep duplicate
parts and missing parts visible. A reconstruction with a part missing is partial
and names the missing numbers; do not read the whole from a fragment, which can
mean something other than the whole. Do this per source log: record ids and block
ids from two machines or two log generations are not one sequence.

**What a 4104 shows.** That the engine compiled this text, in this host, under this
account (the Security `UserID` is in the XML). It does not show that every
statement ran, that it succeeded, or what it did: a function definition, a
commented block, a script that failed at line one all produce one. Its Level says
how the engine classed the block, not whether it was malicious. Establish an action
from invocation and outcome evidence: the launch (4688 with a command line where
audited, 400's HostApplication, `execution/prefetch`), the process's other records,
and the effect on the system.

**`ConsoleHost_history.txt`.** A plain-text file per user, written by PSReadLine,
not an event log: clearing the logs does not touch it. It is configurable and
host-specific (other hosts keep their own `<host>_history.txt`; it can be
redirected, disabled, or made to leave out lines), so a missing line is not a
command that was not typed. It has no per-command times and several sessions write
to one file, so it gives an order with possible interleaving, not a clock. The
file's own times (`mft_records`, both time sets, `filesystem/mft`) say when the
file was created and last changed on this volume; they do not bracket a session or
date a line. Record the path, encoding and extent, check each profile that exists,
including service and administrator accounts, and put its lines on the timeline only
beside a source that carries time.

**Encoded commands and an older engine.** An `-EncodedCommand` argument is data: the
encoding for the parameter on the observed host is base64 of UTF-16LE. Decode it
offline, as text, into a file; read it, never run it, never pass it to an
interpreter, never evaluate recovered code. Keep the encoded form as the artefact
and the decoded text as a derivative whose transformation you record. A request for
the older engine (`-Version 2` in a command line, or an EngineVersion of 2.0 in
400) shows a request or a start, not that the engine was installed or that logging
was absent; availability and logging differ by build and by installed features. Ask
what the launching context was: legacy applications can request an older engine.
Changes to Defender or other controls arise through policy, management software
and interfaces other than PowerShell; read their own records
(`antiforensics/traces`).

**Bounded negative.** "No evidence of <behaviour or term> was found in <the
Operational and classic logs, history files and transcripts examined>, <first to last
record time>; script block logging was <shown on, shown off, not established>;
`parse_errors` <n>." Add the profiles checked and the logs the case did not supply.

**Sensitive output.** Command lines, script text and decoded commands can hold
credentials, tokens or keys. Run `evtx_query` over these logs, and any decoding, as
jobs with `secret_output: true`; cite the record (file, channel, record id,
`record_offset`) and describe the behaviour; never write a secret's value, a
fragment, or a hash of it, and never the encoded form of a command that holds one.

**Does not show.** From these records: who typed or ran the text, intent, that the
code completed or had an effect, that a missing command was never run, or that the
logs and history are whole. A history file is the host's own record of what it
chose to save.
