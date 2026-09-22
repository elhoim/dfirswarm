#!/usr/bin/env python3
"""Score a series of connection times for the regularity that gives a beacon away.

Command and control is invisible in any one session and obvious across many. The
signal is timing, and the measure that works on modern implants is not "are the
intervals identical" — they randomise, typically "sleep 3600, jitter 20 per
cent" — but "how tightly do the intervals cluster around their own median".

So this reports the median interval, the median absolute deviation, and the
deviation as a fraction of the median. A fraction near zero is a fixed timer;
up to about a quarter is a jittered beacon; above that is ordinary traffic.

It also reports the two things people forget to look at: whether the series
covers enough time to mean anything, and whether it stopped. A regular pattern
that ends abruptly is often the moment the operator moved to another channel,
and that timestamp belongs in the timeline.

What it cannot do is tell you the destination is hostile. Update checks,
telemetry, NTP, revocation checks and monitoring agents all beacon beautifully.
The finding is periodicity plus something that does not belong.
"""
import datetime
import json
import statistics
import sys


def fail(message, **extra):
    print(json.dumps({"error": message, **extra}))
    raise SystemExit(1)


def seconds(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if isinstance(value, str):
        text = value.strip()
        try:
            return float(text)
        except ValueError:
            pass
        try:
            parsed = datetime.datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if not parsed.tzinfo:
            parsed = parsed.replace(tzinfo=datetime.timezone.utc)
        return parsed.timestamp()
    return None


def iso(stamp):
    try:
        return datetime.datetime.fromtimestamp(
            stamp, datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError):
        return None


def main():
    try:
        args = json.load(sys.stdin)
    except ValueError as exc:
        fail("arguments are not valid JSON", reason=str(exc))
    raw = args.get("timestamps")
    if not isinstance(raw, list) or not raw:
        fail("timestamps is required: a list of connection times, epoch seconds or ISO 8601")
    minimum = args.get("min_events", 6)
    if not isinstance(minimum, int) or isinstance(minimum, bool) or minimum < 3:
        fail("min_events must be an integer of at least 3")

    parsed, bad = [], 0
    for value in raw:
        converted = seconds(value)
        if converted is None:
            bad += 1
        else:
            parsed.append(converted)
    if len(parsed) < minimum:
        fail("too few usable times to score", usable=len(parsed), needed=minimum,
             unreadable=bad,
             note="Fewer than a handful of connections cannot show periodicity, and scoring them "
                  "would invent a pattern.")

    parsed.sort()
    intervals = [round(b - a, 6) for a, b in zip(parsed, parsed[1:]) if b > a]
    if not intervals:
        fail("every time is identical, so there are no intervals to measure")

    median = statistics.median(intervals)
    deviations = [abs(i - median) for i in intervals]
    mad = statistics.median(deviations)
    relative = (mad / median) if median else None
    span = parsed[-1] - parsed[0]
    expected = (span / median + 1) if median else None
    coverage = (len(parsed) / expected) if expected else None

    if relative is None:
        shape = "unmeasurable"
    elif relative <= 0.02:
        shape = "fixed timer"
    elif relative <= 0.25:
        shape = "jittered beacon"
    elif relative <= 0.6:
        shape = "loosely periodic"
    else:
        shape = "not periodic"

    # A gap far longer than the median at the end is a series that stopped.
    stopped = None
    if len(intervals) >= 3 and median:
        tail = intervals[-1]
        if tail > median * 4:
            stopped = {"last_regular_event": iso(parsed[-2]),
                       "gap_seconds": tail,
                       "why": "the final interval is more than four times the median: this pattern "
                              "stopped, and the time it stopped belongs in the timeline"}

    print(json.dumps({
        "label": args.get("label"),
        "events": len(parsed),
        "unreadable_values": bad,
        "first": iso(parsed[0]), "last": iso(parsed[-1]),
        "span_seconds": round(span, 3),
        "median_interval_seconds": round(median, 3),
        "median_absolute_deviation_seconds": round(mad, 3),
        "jitter_fraction": round(relative, 4) if relative is not None else None,
        "shape": shape,
        "completeness": round(coverage, 3) if coverage else None,
        "intervals_sample": intervals[:40],
        "stopped": stopped,
        "note": "A tight cluster is a timer, not a verdict. Update checks, telemetry, NTP, "
                "revocation checks and monitoring agents are all more regular than most malware. "
                "The finding is periodicity plus something that does not belong: a destination "
                "with no business relationship, a process on the host that should not be talking, "
                "a name registered last week. Completeness below 1 means connections are missing "
                "from the series, which usually means the capture rolled.",
    }, indent=2))


if __name__ == "__main__":
    main()
