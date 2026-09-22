---
id: sessions/reconstruct
title: Putting a session back together
when: You need what was actually sent, not just who spoke to whom.
needs: [capture/what-you-have]
tools: [pcap_summary, zeek_run]
requires_host: [tcpflow, tshark]
---

A conversation in the summary is an address pair and a byte count. A session is
the bytes in order, and getting there has three traps.

**Reassembly is not concatenation.** TCP segments arrive out of order, are
retransmitted, and overlap. A naive join produces a stream that never existed,
and where the overlap differs between copies — which is a deliberate evasion —
the reassembly you choose changes what the content says. Use `tcpflow` or
`tshark -z follow`, and say which, because two tools can legitimately disagree.

**Most of it is encrypted, and that is fine.** You will not read a TLS payload.
What you can still establish is in `metadata/dns-tls`: the name requested, the
certificate, the sizes and the timing. Do not spend the case trying to decrypt
what you can characterise instead.

**A file carved from a stream needs its own provenance.** When you recover an
object, record the stream it came from — both endpoints, both ports, the start
time — and hash it. An extracted file with no session behind it is worth
nothing in a report.

What is worth reconstructing, in order: anything over plain HTTP; SMB, which
carries file names even where the data is signed; FTP and its data channel;
plain-text protocols on unexpected ports, which is a tell in itself; and DNS,
which carries payloads more often than people expect.

Where `zeek` is on the host, run it first. Its `files.log` already names every
object it reassembled, with a hash, and `conn.log` gives you the session behind
each one. That is an hour saved on every capture.
