#!/usr/bin/env python3
"""Read CloudTrail, and follow the identity back to a person.

Two things this exists to do properly.

**Resolve the assumed role.** userIdentity.type of AssumedRole names a session,
not a human. The sessionContext carries the role that was assumed and when, and
the AssumeRole call earlier in the log carries who assumed it. Attribution that
stops at the session name attributes an action to a role, which is not an
answer.

**Count the refusals.** errorCode is the loudest signal in CloudTrail and the
one a summary by eventName hides: an identity making a hundred calls and being
refused ninety of them is mapping its own permissions, and that is usually the
first hour of an intrusion.

Management events are on by default and data events are not, so GetObject is
usually absent. That is a fact about the trail's configuration and it belongs in
the report, because "was the data read" is otherwise unanswerable.
"""
import gzip
import json
import os
import re
import sys

NOTABLE = {
    "ConsoleLogin": "a console sign-in; check MFAUsed",
    "CreateAccessKey": "a long-lived credential was created",
    "CreateUser": "an account was created",
    "CreateLoginProfile": "a console password was set on an account",
    "AttachUserPolicy": "a policy was attached to a user",
    "AttachRolePolicy": "a policy was attached to a role",
    "PutUserPolicy": "an inline policy was written",
    "CreatePolicyVersion": "a policy was changed",
    "UpdateAssumeRolePolicy": "who may assume a role was changed",
    "PutBucketPolicy": "a bucket policy was changed",
    "PutBucketAcl": "a bucket ACL was changed",
    "PutBucketPublicAccessBlock": "public access settings were changed",
    "ModifySnapshotAttribute": "a snapshot was shared, possibly with another account",
    "ModifyImageAttribute": "an image was shared",
    "DeleteTrail": "a trail was deleted",
    "StopLogging": "logging was stopped: the gap that follows is the finding",
    "UpdateTrail": "a trail was changed",
    "GetSecretValue": "a secret was read",
    "Decrypt": "a key was used to decrypt",
    "AssumeRole": "a role was assumed",
    "DeleteDetector": "GuardDuty was disabled",
    "DisableSecurityHub": "Security Hub was disabled",
    "RunInstances": "an instance was started",
}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def load(path):
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        text = fh.read()
    try:
        loaded = json.loads(text)
    except ValueError:
        out = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        return out
    if isinstance(loaded, dict) and "Records" in loaded:
        return loaded["Records"]
    return loaded if isinstance(loaded, list) else [loaded]


def identity_of(record):
    who = record.get("userIdentity") or {}
    out = {"identity_type": who.get("type"), "arn": who.get("arn"),
           "account": who.get("accountId"), "user_name": who.get("userName"),
           "principal": who.get("principalId")}
    session = (who.get("sessionContext") or {})
    issuer = session.get("sessionIssuer") or {}
    if issuer:
        out["assumed_role"] = issuer.get("arn") or issuer.get("userName")
        out["role_account"] = issuer.get("accountId")
    attributes = session.get("attributes") or {}
    if attributes:
        out["session_started"] = attributes.get("creationDate")
        out["mfa"] = attributes.get("mfaAuthenticated")
    if who.get("invokedBy"):
        out["invoked_by"] = who["invokedBy"]
    return {k: v for k, v in out.items() if v not in (None, "")}


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a CloudTrail file or a directory of them")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    wanted = {str(e) for e in (args.get("events") or [])}
    pattern = None
    if args.get("identity"):
        try:
            pattern = re.compile(args["identity"], re.I)
        except re.error as exc:
            fail("identity is not a valid regex", reason=str(exc))

    targets = []
    if os.path.isdir(path):
        for dirpath, _dirs, names in os.walk(path):
            for name in sorted(names):
                if name.endswith((".json", ".json.gz", ".gz")):
                    targets.append(os.path.join(dirpath, name))
    else:
        targets = [path]
    if not targets:
        fail("no CloudTrail files there", path=path)

    records, by_event, by_identity, by_address, errors = [], {}, {}, {}, {}
    read, unreadable, truncated = 0, 0, False
    first = last = None
    for target in targets:
        try:
            rows = load(target)
        except (OSError, ValueError):
            unreadable += 1
            continue
        for row in rows:
            if not isinstance(row, dict):
                continue
            read += 1
            who = identity_of(row)
            entry = {
                "time": row.get("eventTime"),
                "event": row.get("eventName"),
                "source": row.get("eventSource"),
                "region": row.get("awsRegion"),
                "address": row.get("sourceIPAddress"),
                "user_agent": row.get("userAgent"),
                "error": row.get("errorCode"),
                "error_message": row.get("errorMessage"),
                "read_only": row.get("readOnly"),
                "event_id": row.get("eventID"),
                "source_file": target,
                **who,
            }
            parameters = row.get("requestParameters")
            if isinstance(parameters, dict) and parameters:
                entry["request"] = {k: parameters[k] for k in list(parameters)[:10]}
            if row.get("eventTime"):
                first = row["eventTime"] if first is None else min(first, row["eventTime"])
                last = row["eventTime"] if last is None else max(last, row["eventTime"])
            name = entry["event"] or "?"
            by_event[name] = by_event.get(name, 0) + 1
            actor = entry.get("arn") or entry.get("user_name") or entry.get("identity_type") or "?"
            by_identity[actor] = by_identity.get(actor, 0) + 1
            if entry.get("address"):
                by_address[entry["address"]] = by_address.get(entry["address"], 0) + 1
            if entry.get("error"):
                errors.setdefault(actor, {})
                errors[actor][entry["error"]] = errors[actor].get(entry["error"], 0) + 1
            note = NOTABLE.get(name)
            if note:
                entry["notable"] = note
            if wanted and name not in wanted:
                continue
            if args.get("notable_only") and not note:
                continue
            if args.get("errors_only") and not entry.get("error"):
                continue
            if pattern and not pattern.search(actor):
                continue
            if len(records) >= limit:
                truncated = True
                break
            records.append({k: v for k, v in entry.items() if v not in (None, "")})
        if truncated:
            break

    denial = [{"identity": who, "errors": counts, "total": sum(counts.values())}
              for who, counts in errors.items()]
    denial.sort(key=lambda d: -d["total"])
    top = lambda d, n=20: [{"value": k, "count": v}
                           for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:n]]
    print(json.dumps({
        "files": len(targets), "rows_read": read, "unreadable_files": unreadable,
        "records": records, "record_count": len(records),
        "first_event": first, "last_event": last,
        "by_event": top(by_event, 30), "by_identity": top(by_identity),
        "by_address": top(by_address),
        "refusals_by_identity": denial[:20],
        "truncated": truncated,
        "note": "An AssumedRole identity names a session, not a person: assumed_role and "
                "session_started are resolved above, and the AssumeRole call earlier in the log "
                "says who assumed it. Follow that chain before attributing anything. A high "
                "refusal count against one identity is the shape of permission enumeration. "
                "Management events are on by default and data events are not, so GetObject is "
                "usually absent — say so rather than reporting that nothing was read.",
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
