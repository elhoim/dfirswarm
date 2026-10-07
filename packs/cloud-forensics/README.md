# Cloud and SaaS Forensics Pack

Logs that belong to somebody else's computer: what each provider keeps, for how
long, and what the absence of a log actually means.

Depends on the Computer Forensics Base Pack.

## What it carries

**Six skills**: `logs/what-exists`, `m365/unified-audit-log`, `entra/signins`,
`aws/cloudtrail`, `google/workspace`, `identity/tokens`.

**Three tools**, all readers of exports that were supplied (nothing here connects to a tenant). `ual_parse` reads a
Microsoft 365 unified audit log export and opens the `AuditData` payload, keeping the whole of it beside the fields it
lifts out. `cloudtrail_parse` reads CloudTrail records and links each assumed-role session to the successful
AssumeRole calls in the records that could have issued it, as a candidate with its basis and never as attribution to a
person. `signin_analyse` reads an Entra or Google Workspace login export, keeps each record's ids, authentication
details and applied policies, and lists leads (a success that recorded one factor, failures shortly before a success, an
address seen once in the export, two successes whose coordinates imply a high speed), each a hypothesis bounded by what
the export holds. Each says what it did not read, keeps every record with its file, record and line, withholds a value
named or shaped like a credential, and writes a whole result only under the run's output place.

**One goal template**: `tenant-compromise.md`.

## What this pack exists to stop

**Reporting that access stopped without proving it.** Refresh-token behaviour
depends on the identity provider, token type, and revocation action. OAuth
consent is a separate grant and must be reviewed and revoked explicitly; a
mailbox rule can keep acting with no interactive session. `identity/tokens` is
the skill, and the goal template will not pass its checks without evidence of
the relevant revocation action.

**Reporting a retention gap as a finding.** Defaults vary by service, licence,
event date, and tenant policy. For example, current Purview Audit (Standard)
defaults to 180 days for records generated since 17 October 2023, Entra keeps
sign-ins for 7 days on Free and 30 days on P1/P2, and CloudTrail Event History
keeps 90 days of regional management events. Record the tenant's effective
settings and export time before interpreting a quiet period.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/cloud-forensics
    scripts/swarm.sh start --pack computer-forensics-base,cloud-forensics ...
