---
id: antiforensics/traces
title: Investigating possible evidence removal or manipulation
when: Artefacts are missing or inconsistent and you need to distinguish deliberate action from ordinary retention, configuration or collection limits.
needs: [filesystem/deleted, logs/security]
tools: [regkv, evtx_query, evtx_carve, prefetch_mam, amcache_apps, vss_stores, mft_records, usn_journal]
requires_host: []
---

A first pass that found nothing, or a record that looks wrong, is an observation to
explain, not yet a finding of concealment. Most absences and inconsistencies come
from what was never recorded, was kept for a short time, was removed by routine
maintenance, was missed by the collection or was not read by the parser. Work the
explanations in that order and move to deliberate action only on evidence that
separates it from them.

**Before you call an absence.** State the detection opportunity for each missing
artefact. Was it meant to be recorded here (the feature enabled, the audit policy
or channel configured, the software installed)? How long is it kept (log size and
rollover, a journal or cache that wraps)? Was it in the acquisition (the profile,
volume, hive, channel and generation you were given, with their sidecars and
logs)? Did the parser read it (`status`, `parse_errors`, `problems`,
`structural_errors`: a partial or failed run is a coverage condition, not a
negative)? Is there routine removal (cleanup tasks, storage management, product
updates, backup or management software)? Only what survives these questions is a
candidate for deliberate action, and then it needs corroboration that names the
action.

**Wording a negative.** "No evidence of X was found in `<objects, acquisition,
interval>` by `<tool and query>`, which would have recorded it only if
`<condition>`." Absence of an artefact is not absence of the event. Never write
"cannot be recovered" from one failed route: list the routes tried
(`filesystem/deleted`, `logs/recovery`, `filesystem/shadowcopies`, carving) and
what each returned.

**Overwriting or wiping tools.** Observation: records or files with
repeated-character names, high-entropy content, or an execution artefact for a
deletion utility (`prefetch_mam`, `amcache_apps`). These are leads. High entropy is
also what encryption, compression and archives look like, and repeated names come
from software that makes temporary or placeholder names. A Prefetch entry shows a
program was launched under that name (the hash in its file name is of the path, not
of the content); an Amcache entry shows it was inventoried, and `amcache_apps`
returns the hash as stored without establishing which range of the file it covers,
so a match is a lead and a mismatch is no exclusion. Neither says which files were
overwritten or that recovery is impossible. A renamed utility is identified from the
recovered file's content (hash, PE metadata), not its name. Separate with the
utility's configuration and target list, MFT record reuse and sequence numbers
(`mft_records`), change-journal records for the affected names (`usn_journal`) and
what remains in unallocated space (`filesystem/deleted`).

**Log clearing.** Observation: a clearing event (Security 1102, System 104, each
qualified by its provider) naming a subject account, or a channel that is empty or
absent. A clearing event is evidence to interpret: report what it recorded (subject
fields, time), not the content that was removed. An empty channel does not separate
clearing from a channel never enabled, rollover at its size limit, a log that was not
collected, forwarding in place of local storage, corruption or a parse failure.
Separate them with the channel's configuration (enabled state, size and retention in
the SOFTWARE and SYSTEM hives, read with `regkv`; confirm the key names on this
build), the file's own times and size, the counts `evtx_query` reports
(`records_examined`, `events_matched`, `parse_errors`) with the first and last record
time, and records carved from unallocated space, a pagefile or a shadow copy
(`evtx_carve`, `logs/recovery`). A gap in `EventRecordID` within one file means
records are absent from that file; it is not a count of events. Report "no matching
events were found in `<files, interval>`" with the detection opportunity, then
recover.

**Snapshots removed.** Observation: `vss_stores` lists no stores. First separate a
failed enumeration (`status: failed`, exit 1; the exporter's exit status, its whole
output and the claimed-against-read store counts are the evidence) from one that
exited 0 and itself reported zero stores. That is what this reader found at this
volume offset, not proof that none existed. Zero stores also fits snapshots never
enabled for the volume, removal under storage pressure or a quota, the wrong volume
or offset, and removal by software or an administrator. A command line that deletes
snapshots (the built-in `vssadmin`, WMI or PowerShell equivalents) in process
creation events, PowerShell logging or other process telemetry shows an attempted
operation, not that it succeeded: look for the outcome in the surviving stores and
the service and provider events, where logged. Recognise such a command by what it
does; never run one. `filesystem/shadowcopies` has the rest.

**Timestamp manipulation.** `mft_records` returns the `$STANDARD_INFORMATION` and
`$FILE_NAME` times side by side (raw FILETIME and ISO UTC, seven fractional digits);
`timestomp_only` keeps records where they disagree, and its `si_` flags are
indicators, not proof. A modification time before the creation time is ordinary
after a copy, an extraction or a restore, installers, archivers and backup software
set times, and the two sets are written by different operations. Compare the raw
values with independent records for the same file reference and sequence:
`usn_journal` records, event logs, Prefetch, application records, another copy of the
file, allowing for copying, restoration, extraction and clock error. A record with
`structural_errors`, or one whose `$ATTRIBUTE_LIST` is unresolved, is not compared as
if it were whole. This pack does not decode `$LogFile`: say it was not examined, and
do not offer it as a clock.

**Clock changes.** Security 4616, where auditing records it, gives the previous and
new time and the process that changed it. A clock change makes times in the affected
interval uncertain; it does not make every wall-clock value unusable. Record the
before and after values, the process and account, and the interval; then say which
sources use the system clock (event times, file times written then) and which use
another (an external time source, another host, a hypervisor host). Event record ids,
USNs and sequence numbers order records inside their own source and generation and
are not a common clock between sources. Alternatives to deliberate action: time
synchronisation, a guest-integration service, manual correction, a zone or
daylight-saving change.

**A deleted virtual machine.** A recovered disk header names a candidate container;
it does not show that the logical sectors can be rebuilt. Inventory configuration
files, hypervisor logs, snapshot and backing-disk chains and the extents that
survive (`filesystem/carving`). Keep the mapping from recovered bytes to their source
offsets, validate the container and the guest file system, and report missing
extents and backing files. Attribute recovered guest events to the guest only when
their structure and provenance support it; `evtx_carve` reads carved chunks, and a
record still belongs to the channel it names.

**Security-control changes.** Observation: an exclusion added or protection turned
off. Examine the antivirus product's operational events, its policy and
configuration (exclusion and policy keys in the SOFTWARE hive, read with `regkv`),
service events, process telemetry and PowerShell records (`logs/powershell`,
`logs/security`). Separate a requested change from an effective one and from a
blocked attempt. `ConsoleHost_history.txt` of PSReadLine is optional, configurable
and limited to hosts that support it; it holds commands typed, not their output or
success, and it is not an event log, so clearing the logs does not touch it, but
neither its survival nor its absence is guaranteed. Compare with approved
administration (group policy, management software, installers) before attributing a
change to an intruder.

**The examiner's own artefacts.** A driver, service, Prefetch entry or file made by
acquisition, mounting or collection is not subject activity. Check names and times
against the acquisition and collection records (`evidence/collections`) before you
attribute one.

**What corroborates.** "Cleared" needs the clearing record with its subject and a
coverage gap consistent with it. "Timestomped" needs the disagreement, an
independent source for the true time and the ordinary explanations excluded.
"Deliberate" needs an identified account performing the action and no administrative
explanation. Write each as observation, inference and conclusion, with the
alternatives that remain.

**Sensitive output.** `regkv`, `evtx_query`, `evtx_carve` and `mft_records` with
`with_resident` can reach command lines, script text and file content that hold
secrets. Run them as jobs with `secret_output: true`, and describe a secret by where
it sits, its kind, length and what it grants, never its value, a fragment or a hash.
Recovered commands and scripts are read, decoded offline if need be, and never run.

**Does not show.** Who, why, or even that something was removed: an empty channel, a
missing store, a gap in record ids and a timestamp disagreement each have ordinary
causes. A clearing event shows a clear, not what was lost or that nothing else was
altered; a command line shows an attempt, not its success; an execution artefact for
a wiping tool does not say which files; an absent artefact is not an absent event.
