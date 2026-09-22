---
id: beacons/periodicity
title: Finding the thing that calls home
when: You suspect command and control, or a first pass found nothing.
needs: [metadata/dns-tls]
tools: [beacon_score, pcap_summary]
requires_host: []
---

Command and control looks like nothing in any one session. It is only visible
across many, and the signal is **timing, not content**.

Feed the connection times for one pair to `beacon_score`. It returns the median
interval, the jitter around it, and a score. What to look for:

- **A tight interval with low jitter.** Sixty seconds, plus or minus two, for
  four hours. Almost nothing legitimate is that regular.
- **A wide interval with proportional jitter.** Modern implants randomise —
  "sleep 3600, jitter 20 per cent" — so the intervals scatter but the
  *distribution* stays narrow and centred. That is what the score measures.
- **Tiny, symmetrical transfers.** A few hundred bytes each way, every time,
  with occasional large outliers where a task ran.

And what produces false positives, because they are most of what you will find:
software update checks, telemetry, NTP, certificate revocation checks, mail
polling, and monitoring agents. All of them beacon beautifully.

So the finding is never the periodicity alone. It is periodicity **plus**
something that does not belong: a destination with no business relationship, a
process on the host that should not be talking, a certificate that is wrong, a
name registered last week, a user agent that matches nothing else on the estate.

Two practical points. Use **connection start times**, not packet times, or
keep-alives swamp the signal. And check for a beacon that stopped: a regular
pattern that ends abruptly is often the moment the operator moved to another
channel, and that timestamp belongs in the timeline.
