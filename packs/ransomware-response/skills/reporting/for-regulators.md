---
id: reporting/for-regulators
title: Evidence-led reporting and notification assessment
when: Preparing incident findings for legal, regulatory, insurance or executive review.
needs: []
tools: []
requires_host: []
---

Use when you prepare incident findings for legal, regulatory, insurance or executive review. Not for the clocks and duties or the conclusions; read `reporting/citations` for how to cite.

Keep one controlled evidentiary record and prepare each audience's disclosure from
it. Record every report's purpose, recipients, revision, approval and evidence
cut-off. A label ("privileged", "confidential") or a shared draft establishes
neither privilege nor confidentiality: the legal owner decides what goes to whom.

**Assess every harm, not only exfiltration.** Describe confidentiality, integrity
and availability effects separately, with the affected services, the categories
of personal data, the populations and the business consequences. As GDPR's definition of a
personal-data breach reads, and as similar laws may read, a loss of availability or
integrity can qualify, so ransomware can be reportable with no evidence that
anything left; check the definition against the current text. Uncertainty
about exfiltration does not justify postponing the notification assessment: it
goes into the report as a stated unknown.

Do not wait for the final forensic report when an initial notification may be due:
state what is known, what is under investigation, what was not examined and when
an update is expected.

Only for the clocks and the register of duties: `reporting/notification-register`. Only if you write the phase-by-phase conclusions, a bounded negative or the insurance and control findings: `reporting/conclusions-and-controls`.

**Sensitive output.** Keep the adversary's claims, ransom notes and victim
identifiers out of the body of the report. Cite where each is (note id, offset,
the sealed job output that holds it); an exhibit under access control holds a
value only where the operator asks for it by name. This skill authorises no contact
with the adversary, no payment, no negotiation and no external submission of case
material.

Never write a credential's value or its hash in the report, the ledger or the
board: that covers a key, token or password found in a note, an environment or a
store, and the hash of one. Write where it was, its type and length, what it
grants and the rotation it needs, and cite the sealed output. Jobs that extract
keys or credentials run with `secret_output: true`.

Include the response-action log: what was isolated, shut down, repaired, restored
or rebuilt, who authorised it, when, and what evidence that cost. State the
remaining access concerns and the restoration limits, with reasons.

**Does not show.** A report does not show that a duty was met, or applies; that
data left because it could have; or that access ended because the search stopped.
