---
id: identity/tokens
title: Tokens, consents, and why a password reset did not help
when: The account was recovered but the access continued.
needs: [entra/signins]
tools: [ual_parse, signin_analyse]
requires_host: []
---

This is the single most common failure in cloud incident response. The account
is compromised, the password is reset, multi-factor is enforced — and the
attacker is still in, because none of those revoke what they actually hold.

**A refresh token survives a password reset.** It is a bearer credential with
its own lifetime, and on Entra it is only invalidated by an explicit revocation
(`Revoke-MgUserSignInSession`, or revoking refresh tokens in the portal). The
same is true of a Google OAuth grant. Sign-ins using one appear in the
**non-interactive** log, which is a separate export, so an examiner looking only
at interactive sign-ins sees the access stop when it did not.

**An application consent survives everything.** "Consent to application" in the
unified audit log, or a Token audit entry in Workspace, means the user granted a
third-party application access to their mail or files. That application keeps
working after the password change, after the session revocation, and after the
device is wiped. Illicit consent grants are a whole attack pattern and the
artefact is one row in an audit log.

**A mailbox rule survives too**, and it is quieter than either. A rule that
forwards to an external address, or moves anything matching "invoice" to a
folder and marks it read, keeps working with no session at all.

So the questions a cloud report must answer, in this order:

1. What sessions and refresh tokens existed, and were they revoked? When?
2. What applications hold a consent, with which scopes, granted by whom and when?
3. What mailbox rules, filters and forwarding addresses exist, and when was each
   created?
4. What delegations and mailbox permissions were added?
5. What did the attacker do that survives their access entirely — a shared
   Drive link, a downloaded archive, a created account?

And the timeline must say when each was **revoked**, not only when it was
created. "The password was reset at 14:02 and refresh tokens were revoked at
18:40" describes a four-hour window in which the attacker still had access, and
that window is usually where the rest of the incident happened.
