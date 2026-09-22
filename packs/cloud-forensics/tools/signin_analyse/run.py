#!/usr/bin/env python3
"""Read a sign-in log and surface the four things that decide a cloud case.

**A success that satisfied one factor** on a tenant that requires two. Either a
legacy protocol was used, a policy exempted the application, or the session came
from a stolen token — and any of those is the finding.

**Failures then a success.** A run of multi-factor prompts followed by an
acceptance is what consent fatigue looks like from the log's side; a run of
wrong passwords followed by a success is a different story with the same shape.
Both are worth surfacing and neither is a conclusion.

**An address or a client seen nowhere else** for that account, against its own
history rather than against a global idea of "unusual".

**Impossible travel**, which is a hypothesis and not a conclusion. Two sign-ins
from distant countries minutes apart is also what a VPN, a mobile carrier's
routing and a cloud-hosted mail client look like. The implied speed is computed
so the claim is measurable, and the output says what would turn it into a
finding.

Coordinates are used where the export carries them; where it carries only a
country, pairs are flagged on the country change alone and marked as coarse.
"""
import csv
import datetime
import json
import math
import os
import re
import sys

SINGLE = "singlefactorauthentication"
CODES = {
    "0": "success", "50053": "account locked", "50055": "password expired",
    "50056": "invalid or null password", "50074": "a second factor was required",
    "50076": "multi-factor required, user prompted",
    "50079": "multi-factor enrolment required",
    "50126": "wrong user name or password", "50158": "conditional access failed",
    "53003": "blocked by conditional access", "65001": "no consent for the application",
    "700016": "application not found in the directory",
}


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def get(row, *names):
    for name in names:
        for key in row:
            if key and key.replace(" ", "").lower() == name.replace(" ", "").lower():
                value = row[key]
                if value not in (None, ""):
                    return value
    return None


def when(value):
    if not value:
        return None
    try:
        parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        for form in ("%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%d/%m/%Y, %H:%M:%S"):
            try:
                parsed = datetime.datetime.strptime(str(value), form)
                break
            except ValueError:
                continue
        else:
            return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.timezone.utc)


def distance(a, b):
    """Great-circle kilometres between two (lat, lon) pairs."""
    lat1, lon1 = math.radians(a[0]), math.radians(a[1])
    lat2, lon2 = math.radians(b[0]), math.radians(b[1])
    h = math.sin((lat2 - lat1) / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2 - lon1) / 2) ** 2
    return 6371.0 * 2 * math.asin(min(1.0, math.sqrt(h)))


def rows_from(path):
    if path.lower().endswith(".json"):
        with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
            try:
                loaded = json.load(fh)
            except ValueError:
                fh.seek(0)
                return [json.loads(l) for l in fh if l.strip()]
        if isinstance(loaded, dict) and "value" in loaded:
            return loaded["value"]
        return loaded if isinstance(loaded, list) else [loaded]
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as fh:
        return list(csv.DictReader(fh))


def flatten(row):
    out = dict(row)
    location = row.get("location")
    if isinstance(location, dict):
        out["city"] = location.get("city")
        out["country"] = location.get("countryOrRegion")
        point = location.get("geoCoordinates") or {}
        out["latitude"], out["longitude"] = point.get("latitude"), point.get("longitude")
    status = row.get("status")
    if isinstance(status, dict):
        out["errorcode"] = status.get("errorCode")
        out["failurereason"] = status.get("failureReason")
    device = row.get("deviceDetail")
    if isinstance(device, dict):
        out["device"] = device.get("displayName") or device.get("deviceId")
        out["operatingsystem"] = device.get("operatingSystem")
        out["browser"] = device.get("browser")
    return out


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    path = args.get("path")
    if not isinstance(path, str) or not path:
        fail("path is required: a sign-in log export")
    if not os.path.isfile(path):
        fail("no such file", path=path)
    limit = args.get("limit", 500)
    if not isinstance(limit, int) or isinstance(limit, bool) or limit < 1:
        fail("limit must be a positive integer")
    ceiling = args.get("max_speed_kmh", 900)
    if not isinstance(ceiling, (int, float)) or isinstance(ceiling, bool) or ceiling <= 0:
        fail("max_speed_kmh must be a positive number")
    pattern = None
    if args.get("user"):
        try:
            pattern = re.compile(args["user"], re.I)
        except re.error as exc:
            fail("user is not a valid regex", reason=str(exc))

    try:
        raw = rows_from(path)
    except (OSError, ValueError) as exc:
        fail("that export could not be read", path=path, reason=str(exc))

    events = []
    for row in raw:
        if not isinstance(row, dict):
            continue
        flat = flatten(row)
        account = get(flat, "userPrincipalName", "user", "User", "userDisplayName",
                      "Username", "email", "actor_email")
        if pattern and not pattern.search(str(account or "")):
            continue
        stamp = when(get(flat, "createdDateTime", "Date (UTC)", "time", "Timestamp", "date"))
        code = str(get(flat, "errorcode", "Status", "resultType", "status") or "0")
        events.append({
            "time": stamp.isoformat().replace("+00:00", "Z") if stamp else None,
            "_when": stamp,
            "user": account,
            "application": get(flat, "appDisplayName", "Application", "resourceDisplayName"),
            "address": get(flat, "ipAddress", "IP address", "ip", "sourceIP"),
            "country": get(flat, "country", "Location", "location"),
            "city": get(flat, "city"),
            "latitude": get(flat, "latitude"), "longitude": get(flat, "longitude"),
            "client": get(flat, "clientAppUsed", "Client app", "userAgent", "browser"),
            "device": get(flat, "device", "deviceDetail"),
            "authentication": get(flat, "authenticationRequirement", "Authentication requirement"),
            "conditional_access": get(flat, "conditionalAccessStatus"),
            "result_code": code,
            "result": CODES.get(code, "code %s" % code),
            "success": code in ("0", "Success", "success"),
        })

    by_user = {}
    for event in events:
        by_user.setdefault(event["user"], []).append(event)

    single_factor, bursts, travel, unfamiliar = [], [], [], []
    for user, series in by_user.items():
        series.sort(key=lambda e: e["_when"] or datetime.datetime.min.replace(
            tzinfo=datetime.timezone.utc))
        for event in series:
            if event["success"] and str(event.get("authentication") or "").replace(
                    " ", "").lower() == SINGLE:
                single_factor.append(event)
        # failures immediately before a success
        run = 0
        for event in series:
            if not event["success"]:
                run += 1
                continue
            if run >= 3:
                bursts.append({"user": user, "failures_before": run,
                               "succeeded_at": event["time"], "address": event["address"],
                               "result": event["result"]})
            run = 0
        seen_addresses, seen_clients = {}, {}
        for event in series:
            seen_addresses[event["address"]] = seen_addresses.get(event["address"], 0) + 1
            seen_clients[event["client"]] = seen_clients.get(event["client"], 0) + 1
        for event in series:
            if event["success"] and seen_addresses.get(event["address"], 0) == 1 and len(seen_addresses) > 2:
                unfamiliar.append({"user": user, "time": event["time"],
                                   "address": event["address"], "country": event["country"],
                                   "client": event["client"],
                                   "why": "this address appears once in this account's history"})
        previous = None
        for event in series:
            if not event["success"] or not event["_when"]:
                continue
            if previous:
                seconds = (event["_when"] - previous["_when"]).total_seconds()
                if 0 < seconds < 86400:
                    pair = None
                    if all(previous.get(k) is not None for k in ("latitude", "longitude")) and \
                       all(event.get(k) is not None for k in ("latitude", "longitude")):
                        try:
                            km = distance((float(previous["latitude"]), float(previous["longitude"])),
                                          (float(event["latitude"]), float(event["longitude"])))
                        except (TypeError, ValueError):
                            km = None
                        if km is not None and seconds > 0:
                            speed = km / (seconds / 3600)
                            if speed > ceiling and km > 100:
                                pair = {"kilometres": round(km, 1),
                                        "implied_speed_kmh": round(speed, 1), "coarse": False}
                    elif previous.get("country") and event.get("country") and \
                            previous["country"] != event["country"] and seconds < 3600:
                        pair = {"coarse": True,
                                "why": "the export carries a country but no coordinates"}
                    if pair:
                        travel.append({"user": user, "from": {
                            "time": previous["time"], "address": previous["address"],
                            "country": previous["country"], "city": previous.get("city")},
                            "to": {"time": event["time"], "address": event["address"],
                                   "country": event["country"], "city": event.get("city")},
                            "seconds_apart": round(seconds, 1), **pair})
            previous = event

    for event in events:
        event.pop("_when", None)
    print(json.dumps({
        "path": path,
        "events": events[:limit],
        "event_count": len(events),
        "accounts": len(by_user),
        "successes": sum(1 for e in events if e["success"]),
        "failures": sum(1 for e in events if not e["success"]),
        "single_factor_successes": single_factor[:50],
        "failure_bursts_before_success": bursts[:50],
        "addresses_seen_once": unfamiliar[:50],
        "impossible_travel": travel[:50],
        "note": "Impossible travel is a hypothesis. A VPN, a mobile carrier's routing and a "
                "cloud-hosted mail client all produce it, and the implied speed is given so the "
                "claim is measurable rather than asserted. What turns it into a finding is the "
                "rest: an unfamiliar device, a legacy client, a new application, a consent granted "
                "in the same window. A success that satisfied only one factor on a tenant that "
                "requires two is the stronger signal, and it is the first list above.",
    }, indent=2, default=str))


if __name__ == "__main__":
    main()
