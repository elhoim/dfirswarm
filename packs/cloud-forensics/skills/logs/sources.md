---
id: logs/sources
title: Cloud source families to inventory
when: You must list which logs to expect or ask for in a cloud case.
needs: [logs/what-exists]
tools: [cloudtrail_parse, signin_analyse, ual_parse]
requires_host: []
---

Use when you are building the inventory of cloud log sources for a case. Not for judging coverage of one source (use `logs/what-exists`).

Inventory each family on its own line: supplied, not supplied, or disabled, with the evidence for that. A family you did not name here is still a source if the case supplies it.

- **Microsoft:** Purview audit; Entra sign-ins (interactive, non-interactive, service principal and managed identity are separate exports); Entra directory audit; Azure activity and resource logs; message trace; mailbox settings; application grants.
- **Google Workspace:** admin, login, OAuth and token, Drive, Groups, mobile, and the Gmail logs the case supplies, if any.
- **Google Cloud:** Cloud Audit Logs with their sink, bucket and exclusion configuration, and any resource logs.
- **AWS:** CloudTrail management events and the data events that were selected; S3 server access logs; Config history; VPC flow logs; GuardDuty findings.
- **Kubernetes:** API-server audit events with the audit policy and the backend that delivered them, beside any control-plane and workload logs.
- **Every family:** the current configuration, as a snapshot at its collection time; disabled sources, selectors and exclusions; retention that expired; delivery that failed; what the acquisition left out.

This pack reads CloudTrail (`cloudtrail_parse`), Entra sign-ins and Workspace logins (`signin_analyse`) and the Microsoft 365 unified audit log (`ual_parse`). For any other family say that no reader was available, and name the source.

**Does not show:** that a listed family existed in this tenant, or that an unlisted one did not.
