---
id: metadata/dns-tls
title: What you can still prove when the payload is encrypted
when: The traffic is TLS, which is to say most of it.
needs: [capture/what-you-have]
tools: [pcap_summary, zeek_run]
requires_host: [zeek, tshark]
---

You will not read the payload. Four things survive encryption and together they
usually answer the question.

**DNS.** The name that was resolved, when, by which host, and what it answered.
A name is far more useful than an address: addresses are shared, rotate and
belong to hosting providers. Watch for the shapes: a very long label, a high
rate of NXDOMAIN, TXT queries in volume, or a single subdomain pattern repeating
— all of which are what tunnelling and beaconing look like over DNS.

**The TLS handshake, which is not encrypted.** The client hello carries the
server name requested, the cipher list and the extensions; the server hello
carries the chosen cipher and, before TLS 1.3 encrypted it, the certificate. A
self-signed certificate, a certificate whose name does not match the server name
requested, or one with a lifetime measured in days, is worth reporting.

**The fingerprint of how the client speaks.** The ordered set of ciphers and
extensions in a client hello identifies the library, and therefore the
application, across addresses and ports. Two connections from different machines
with an identical unusual fingerprint are the same tool.

**Sizes and timing.** How much went each way, and when. A session that sends 300
bytes and receives 40 every sixty seconds is a beacon whatever it is encrypted
with. See `beacons/periodicity`.

Encrypted DNS removes the first of these: where the host used DNS-over-HTTPS the
names are inside TLS to a resolver, and what remains is the resolver's address
and the timing. Say so rather than reporting that the host made no DNS queries.
