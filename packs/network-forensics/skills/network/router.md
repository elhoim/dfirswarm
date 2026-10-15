---
id: network/router
title: Network notes by question
when: Pick a network note when none is listed, or you cannot choose.
router: true
needs: []
tools: []
requires_host: []
---

Use when the index shows only this line and you need a network note. Not for rules: each note holds its own.

The capture and the logs
`capture/what-you-have` a pcap's scope, integrity, time
`capture/derivatives` filter, split, merge, rebuild
`capture/carve-from-images` no capture, packet buffers in an image
`logs/web-proxy-firewall` text logs, no capture

Content and metadata
`metadata/dns-tls` encrypted traffic, what stays visible
`metadata/fingerprints` JA3, JA4, Suricata match
`sessions/reconstruct` what was actually sent
`sessions/objects` exporting protocol objects

Leads
`beacons/periodicity` calls home on a schedule
`exfil/volume` whether data left, how much
`exfil/counters` what a byte count measures
`correlate/host` tying the wire to host evidence
