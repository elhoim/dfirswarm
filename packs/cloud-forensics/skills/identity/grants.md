---
id: identity/grants
title: Consents, application credentials and mailbox rules as durable state
when: Evidence holds application consents, delegations or mailbox rules that outlive a session.
needs: [logs/what-exists]
tools: [ual_parse, signin_analyse]
requires_host: []
---

Use when the evidence has consent events, application or service-principal records, delegation or mailbox rules and you must say whether they were durable access. Not for token and session revocation (`identity/tokens`). Offline: supplied exports only; never query the tenant.

**A consent event is a lead, not a grant.** `ual_parse` shows the audit records of consents, rules and permissions; `signin_analyse` shows later sign-ins. Verify the event's result, the client and resource ids, the grant type, the scopes or application roles, the consenting principal and any supplied grant state. Tell apart: delegated consent, application permissions, service-principal credentials, federated credentials and domain-wide delegation. Removing a session does not show that any of these was removed; record the removal separately from the revocation.

**Mailbox rules, filters, forwarding and delegations.** A recorded configuration is not evidence it acted: enabled state, conditions, transport restrictions and delivery outcomes decide that. A rule runs without a new sign-in, but its presence alone does not show disclosure. Record when each was created and, separately, when it was removed.

**For each item record:** type, the identifiers in full, scopes or conditions, who created it and when, its last evidenced state, and whether any later activity used it.

**Does not show:** that a grant or rule was used; its state after the last supplied record; a person.

**Sensitive output:** a secret, token or key is described by place, type, length and what it grants, never by value or hash.
