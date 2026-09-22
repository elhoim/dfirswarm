# Cloud and SaaS Forensics Pack

Logs that belong to somebody else's computer: what each provider keeps, for how
long, and what the absence of a log actually means.

Depends on the Computer Forensics Base Pack.

## What it carries

**Six skills**: `logs/what-exists`, `m365/unified-audit-log`, `entra/signins`,
`aws/cloudtrail`, `google/workspace`, `identity/tokens`.

**Three tools.** `ual_parse` reads a Microsoft 365 unified audit log export and
explodes the `AuditData` column — which is JSON, is where almost everything
lives, and is an unreadable blob in a spreadsheet. `cloudtrail_parse` reads
CloudTrail, resolves an assumed role back to the session that issued it, and
counts the refusals that are the shape of permission enumeration.
`signin_analyse` surfaces a success that satisfied one factor on a tenant that
requires two, failure bursts before a success, addresses an account has never
used, and pairs whose implied travel speed is impossible — with the speed
computed, so the claim is measurable rather than asserted.

**One goal template**: `tenant-compromise.md`.

## What this pack exists to stop

**Reporting that access stopped when it did not.** A refresh token survives a
password reset. An OAuth consent survives everything — the reset, the session
revocation, and the device being wiped. A mailbox rule keeps working with no
session at all. `identity/tokens` is the skill, and the goal template will not
pass its own checks without an answer about revocation.

**Reporting a retention gap as a finding.** The unified audit log is 90 days on
common licences, Entra sign-ins 30, and the log arrives up to a day late. A
quiet period at the edge of the window is the licence, not the attacker.

## Install and use

    scripts/pack.sh install packs/computer-forensics-base
    scripts/pack.sh install packs/cloud-forensics
    scripts/swarm.sh start --pack computer-forensics-base,cloud-forensics ...
