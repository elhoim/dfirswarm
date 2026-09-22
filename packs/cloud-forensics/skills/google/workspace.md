---
id: google/workspace
title: Google Workspace
when: The tenant is Google.
needs: [logs/what-exists]
tools: [cloudtrail_parse]
requires_host: []
---

Workspace keeps several separate audit logs and they are exported separately.
Ask for each by name: admin, login, Drive, Gmail, Token, Groups, and Mobile.

    Login audit     every sign-in attempt, the type, the address, and whether
                    a challenge was issued
    Drive audit     view, download, edit, share, and change of visibility; only
                    on the business tiers
    Admin audit     settings changed, users created, roles granted, 2-step
                    enforcement turned on or off
    Token audit     OAuth grants: which application, which scopes, which user —
                    this is the one that matters most and is checked least
    Gmail logs      in BigQuery on the higher tiers, message-level, not content

**The Token audit is where an account is actually kept.** A password change and
a forced sign-out do not revoke an OAuth grant: an application the attacker
authorised keeps its access afterwards. Every incident response here has to
enumerate the grants and their scopes, and `https://mail.google.com/` is full
mailbox access whatever the application is called.

**Drive sharing is the exfiltration route.** Look for a change of visibility to
"anyone with the link", a share to an address outside the domain, and a
download burst from one account. A file shared rather than downloaded leaves
almost nothing on any endpoint, which is why the Drive audit is not optional.

**Gmail filters and forwarding** are the mailbox-rule equivalent: a filter that
forwards and deletes is how a conversation is read without anything appearing in
the sent items. The setting is in the admin audit when an administrator made it
and in the user's own settings when they did.

Two limits to state in the report: the Drive and Gmail logs exist only on
certain tiers, and Workspace retention for most logs is six months. Where a tier
did not include a log, that is what makes a question unanswerable, and it is a
fact about the tenant rather than about the analysis.
