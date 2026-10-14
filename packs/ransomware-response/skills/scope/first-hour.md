---
id: scope/first-hour
title: First-hour scope, containment and preservation
when: Suspected ransomware, destructive encryption or data extortion has just been reported.
needs: []
tools: [encrypted_survey, ransom_note_scan]
requires_host: []
---

Use when suspected ransomware, destructive encryption or data extortion is reported. Not for a single question.

Work containment, evidence preservation, impact assessment and notification
assessment in parallel. Their urgency follows ongoing harm and how fast the
evidence goes, not a fixed order of forensic questions.

**Establish the operating picture.** Record when and by whom the incident was
reported, the organisations and services affected, the business and safety
consequences, and who can authorise a response action. Keep encrypted,
unavailable, isolated, corrupted and merely suspected assets apart. Include
identity services, cloud tenants, backup infrastructure, hypervisors, storage
systems and network storage.

**Contain through the authorised response team.** If encryption, destructive
activity or unauthorised access may be ongoing, escalate at once. Record the
action, who decided it, the assets and the time. Do not hold back necessary
containment for a complete disk image. Isolation, shutdown and continued
operation have different costs: preserve volatile state where feasible and
record what an emergency action will destroy.

**Preserve before restoration changes the sources.** Ask for proportionate
collections from the suspected entry and deployment systems, representative
affected and unaffected endpoints, identity infrastructure, backup servers,
hypervisor and storage management systems and anything that carried outbound
traffic; and for volatile state where feasible, the original logs and their
configuration, central EDR records, remote-access logs, cloud audit exports,
ransom notes and representative affected files. The authorised responder decides
the order; write down the order and what each choice loses. Record the
acquisition authority, source identity, collector and version, time, scope,
failures, custody and integrity check. For a source that is unavailable, record
the request and the limit. A logical collection holds the files it was told to
take; deleted and unallocated data are there only if the volume was acquired.

**Use the pack's tools as triage over an extracted tree.** `encrypted_survey` and
`ransom_note_scan` name candidates; they do not settle scope. Only if you quote a
count from either: `scope/triage-tools`. Only if you order the phases: `scope/phase-timeline`.

Read `exfil/before-encryption`, `encryptor/traces`, `encryptor/destroyed-backups`,
`identify/family`, `recovery/what-is-possible` and `reporting/for-regulators` as the
evidence requires. Notification assessment starts at once and does not wait for
proof of exfiltration or a family name.

**Sensitive output.** `ransom_note_scan` reaches values that can carry access: run it as a job with `secret_output: true`; never write a value or a hash of one.

**Deliver:** an asset-and-service scope table, the phase timeline, the
preservation and containment decision log, an evidence-gap register and the
notification handoff. Say what is established, inferred, partial or not
determinable.

**Does not show.** An incomplete search cannot show that adversary access has ended; a triage count is not the scope.
