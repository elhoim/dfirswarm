---
id: aws/cloudtrail
title: CloudTrail records, coverage and session origin
when: Supplied AWS CloudTrail exports need event interpretation or identity correlation.
needs: [logs/what-exists]
tools: [cloudtrail_parse]
requires_host: []
---

Use when you hold CloudTrail files, lookup-events pages or JSON Lines and must say who did what, from where, and what the export can show. Not for S3 access, VPC flow logs or GuardDuty (say none was read). Offline: never authenticate to the account.

**First, the surface.** Event History results, trail files delivered to a bucket and event data store query results differ in coverage and shape: establish account, region, event categories, selectors and interval from what was supplied. A missing `GetObject` record does not show nothing was read: check data events were captured. `cloudtrail_parse` reads Records files, arrays, JSON Lines, lookup-events pages and gzip; not tar or ZIP.

**Reconcile before any negative.** `status` is complete only if every record of every file was read. Read `coverage`, `file_census`, `rejected_records`, `pagination_markers` (a response naming a next page is one page of more), `digest_files` and `files_not_attempted_named`; cite the file, record and line of every event.

**Fields that carry the case**, beside time, name, source, address and agent: `userIdentity` (`accessKeyId`, `sourceIdentity`, `sessionContext`), `errorCode`, `requestParameters`, `responseElements`, `additionalEventData` (console `MFAUsed`), `recipientAccountId`, `sharedEventID`. The tool keeps them; `outcome` says whether an error was recorded, not whether a change took effect.

**Sessions.** An `AssumedRole` identity names a session, not a person. `session_origin` is a candidate: the successful AssumeRole-family call that returned this session's access key id or ARN, with its `basis` and source event. `unresolved` names every candidate and picks none; `not_found` means none in these files. A failed call is never a source. Who stood behind a session needs the supplied identity-provider evidence (`sourceIdentity`, federation, role chaining), not the parser link.

**Errors.** `error_class` is by the code's name. Repeated authorisation denials are a lead: check identity, services and resources asked for, timing, earlier successes and known automation (inventory jobs and policy changes cause bursts). Throttling, validation and service errors are not denials.

**Flagged calls** (`notable`) name an API, not an effect: credential, identity, policy, ACL, snapshot-sharing and logging calls. Read the result, request and effective configuration before saying what changed. `StopLogging` stops delivery for that trail; it does not delete delivered records or stop other sources: correlate trail scope, selectors, delivery, other trails and the inventory, and keep the observed gap apart from the claim that the call caused it.

**Integrity.** The tool validates no digest file or chain, and a file hash is not that validation: say it was not performed.

**Does not show:** a person; that a call took effect; what was not logged; a complete export.

**Sensitive output:** request and response fields can hold secrets. Run the tool as a job with `secret_output: true`; it withholds credential-named and credential-shaped values and writes originals only with `write_values`. Report an access key id in full, a secret never.
