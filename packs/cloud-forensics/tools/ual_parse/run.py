#!/usr/bin/env python3
"""Read a unified audit log export, and open the column that matters.

The export is CSV with a handful of columns, and one of them — AuditData — is a
JSON document holding almost everything: the client address, the application,
the parameters of the operation, the affected items. Opened in a spreadsheet it
is an unreadable blob, and that is how the detail in a 400,000-row export gets
skipped.

So this explodes it, normalises the fields that appear under different names in
different workloads, and flags the operations that are worth a look on any
tenant: a rule that forwards mail, a consent granted to an application, a
sharing link anyone can use, a mailbox being read.

The flagged list is a starting point, not a detection. Every one of these is
also something an administrator does on an ordinary Tuesday.
"""
import csv
import datetime
import json
import os
import re
import sys

NOTABLE = {
    "New-InboxRule": "a rule was created",
    "Set-InboxRule": "a rule was changed",
    "UpdateInboxRules": "rules were changed from a client",
    "Set-Mailbox": "mailbox settings changed; check ForwardingSmtpAddress",
    "Add-MailboxPermission": "somebody was given access to a mailbox",
    "Add-RecipientPermission": "somebody was given send-as",
    "MailItemsAccessed": "a mailbox was read",
    "Send": "mail was sent from this mailbox",
    "SendAs": "mail was sent as somebody else",
    "Consent to application": "an application was granted access",
    "Add service principal.": "an application identity was created",
    "Add app role assignment grant to user.": "an application was given a role",
    "Add member to role.": "privilege was granted",
    "AnonymousLinkCreated": "a link anyone can use was created",
    "SharingSet": "sharing was changed",
    "AddedToSecureLink": "somebody was added to a sharing link",
    "FileSyncDownloadedFull": "a library was synced in full",
    "FileDownloaded": "a file was downloaded",
    "UserLoggedIn": "a sign-in",
    "UserLoginFailed": "a failed sign-in",
    "Update user.": "an account was changed",
    "Reset user password.": "a password was reset",
    "Disable Strong Authentication.": "multi-factor was turned off",
}
ADDRESS = re.compile(r"^\[?([0-9a-fA-F:.]+)\]?(?::\d+)?$")


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def bound(text, name):
    try:
        parsed = datetime.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        fail("%s must be ISO 8601, e.g. 2026-02-14T00:00:00Z" % name, value=text)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.timezone.utc)


def when(value):
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    for form in (None, "%m/%d/%Y %H:%M:%S", "%d/%m/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            parsed = datetime.datetime.fromisoformat(text) if form is None else \
                datetime.datetime.strptime(str(value), form)
        except (ValueError, TypeError):
            continue
        if not parsed.tzinfo:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed
    return None


def flatten(audit):
    out = {}
    if not isinstance(audit, dict):
        return out
    for key, target in (("Operation", "operation"), ("UserId", "user"),
                        ("ClientIP", "address"), ("ClientIPAddress", "address"),
                        ("ActorIpAddress", "address"), ("Workload", "workload"),
                        ("ResultStatus", "result"), ("Id", "record_id"),
                        ("ObjectId", "object"), ("UserAgent", "user_agent"),
                        ("ClientInfoString", "client"), ("SiteUrl", "site"),
                        ("SourceFileName", "file")):
        if audit.get(key) not in (None, ""):
            out.setdefault(target, audit[key])
    parameters = audit.get("Parameters")
    if isinstance(parameters, list):
        out["parameters"] = {p.get("Name"): p.get("Value") for p in parameters
                             if isinstance(p, dict)}
    for extra in ("ModifiedProperties", "ExtendedProperties"):
        items = audit.get(extra)
        if isinstance(items, list) and items:
            out[extra.lower()] = [
                {"name": i.get("Name"), "new": i.get("NewValue"), "old": i.get("OldValue")}
                for i in items if isinstance(i, dict)][:12]
    folders = audit.get("Folders")
    if isinstance(folders, list):
        out["items_accessed"] = sum(len(f.get("FolderItems") or []) for f in folders
                                    if isinstance(f, dict))
    if audit.get("OperationCount"):
        out["operation_count"] = audit["OperationCount"]
    return out


def rows_from(path):
    if path.lower().endswith(".json"):
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            try:
                loaded = json.load(fh)
            except ValueError:
                fh.seek(0)
                return [json.loads(line) for line in fh if line.strip()]
        return loaded if isinstance(loaded, list) else [loaded]
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        return list(csv.DictReader(fh))


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a unified audit log export, or a directory of them")
    if not os.path.exists(path):
        fail("no such file or directory", path=path)
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    wanted = {str(o) for o in (args.get("operations") or [])}
    pattern = None
    if args.get("user"):
        try:
            pattern = re.compile(args["user"], re.I)
        except re.error as exc:
            fail("user is not a valid regex", reason=str(exc))
    since = bound(args["since"], "since") if args.get("since") else None
    until = bound(args["until"], "until") if args.get("until") else None

    targets = []
    if os.path.isdir(path):
        for dirpath, _dirs, names in os.walk(path):
            for name in sorted(names):
                if name.lower().endswith((".csv", ".json")):
                    targets.append(os.path.join(dirpath, name))
    else:
        targets = [path]
    if not targets:
        fail("no CSV or JSON export there", path=path)

    records, by_operation, by_user, by_address = [], {}, {}, {}
    read, unreadable_audit, truncated = 0, 0, False
    earliest = latest = None
    for target in targets:
        try:
            rows = rows_from(target)
        except (OSError, ValueError) as exc:
            unreadable_audit += 1
            continue
        for row in rows:
            read += 1
            audit = row.get("AuditData") or row.get("auditData") or row.get("AuditData ")
            parsed = {}
            if isinstance(audit, str) and audit.strip():
                try:
                    parsed = json.loads(audit)
                except ValueError:
                    unreadable_audit += 1
            elif isinstance(audit, dict):
                parsed = audit
            entry = {"source_file": target}
            entry.update(flatten(parsed))
            for key, target_name in (("CreationDate", "time"), ("CreationTime", "time"),
                                     ("UserIds", "user"), ("Operations", "operation"),
                                     ("RecordType", "record_type")):
                if row.get(key) not in (None, ""):
                    entry.setdefault(target_name, row[key])
            stamp = when(entry.get("time") or parsed.get("CreationTime"))
            entry["time"] = stamp.isoformat().replace("+00:00", "Z") if stamp else entry.get("time")
            if stamp:
                earliest = stamp if earliest is None else min(earliest, stamp)
                latest = stamp if latest is None else max(latest, stamp)
            operation = entry.get("operation") or "?"
            by_operation[operation] = by_operation.get(operation, 0) + 1
            if entry.get("user"):
                by_user[entry["user"]] = by_user.get(entry["user"], 0) + 1
            if entry.get("address"):
                by_address[entry["address"]] = by_address.get(entry["address"], 0) + 1
            note = NOTABLE.get(operation)
            if note:
                entry["notable"] = note
            if wanted and operation not in wanted:
                continue
            if args.get("notable_only") and not note:
                continue
            if pattern and not pattern.search(str(entry.get("user") or "")):
                continue
            if since and (not stamp or stamp < since):
                continue
            if until and (not stamp or stamp > until):
                continue
            if len(records) >= limit:
                truncated = True
                break
            records.append(entry)
        if truncated:
            break

    top = lambda d, n=20: [{"value": k, "count": v}
                           for k, v in sorted(d.items(), key=lambda kv: -kv[1])[:n]]
    print(json.dumps({
        "files": targets, "rows_read": read,
        "records": records, "record_count": len(records),
        "first_record": earliest.isoformat().replace("+00:00", "Z") if earliest else None,
        "last_record": latest.isoformat().replace("+00:00", "Z") if latest else None,
        "by_operation": top(by_operation, 30),
        "by_user": top(by_user), "by_address": top(by_address),
        "unreadable_audit_data": unreadable_audit,
        "truncated": truncated,
        "note": "The flagged operations are a starting point, not a detection: every one of them "
                "is also something an administrator does on an ordinary Tuesday. Cite the record "
                "Id, because it is what lets somebody find the row again in an export of half a "
                "million. MailItemsAccessed throttles above about a thousand operations an hour "
                "and writes an aggregate instead, so a quiet period in a busy mailbox may be "
                "throttling rather than absence.",
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
