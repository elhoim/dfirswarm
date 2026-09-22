---
id: logs/what-exists
title: What the provider actually keeps, and for how long
when: The evidence is a cloud tenant rather than a machine.
needs: [evidence/verify]
tools: []
requires_host: []
---

There is no disk. Everything you will have is a log the provider chose to keep,
for a period the licence decides, exported by somebody with an administrator
account. Three consequences shape the whole examination.

**Retention is the clock you are racing.** Microsoft 365's unified audit log is
90 days on the common licences and longer on the premium ones; Entra sign-in
logs are 30 days without a subscription that extends them; AWS CloudTrail keeps
90 days of management events in the console unless a trail writes to a bucket,
and data events are off by default. **Say what the retention was, and therefore
what could not have been examined.** A gap at the edge of the window is not a
finding about the attacker.

**The log arrives late.** The unified audit log has a lag of between thirty
minutes and a day depending on the workload. An export taken during an incident
is missing the most recent hours, and an examiner who does not know that reports
that activity stopped.

**Acquisition is somebody exercising an administrator right**, and that is part
of the record. Who exported, with which account, when, over what date range, and
with which tool. Put it in the custody section as you would the imaging of a
disk, and hash the export.

Ask for these, by name, before anything else:

    Microsoft 365   the unified audit log for the whole period, per workload;
                    Entra sign-in and audit logs; mailbox audit; message trace;
                    inbox rules and forwarding; enterprise application consents
    Google          the admin audit, login audit, Drive audit and Gmail logs
    AWS             CloudTrail management and data events, Config, VPC flow logs
    Any             the current configuration, which is evidence of what changed

And ask what was **not** enabled. Mailbox auditing off, no CloudTrail data
events, no Drive audit: each is a set of questions that cannot be answered, and
naming them is part of the answer.
