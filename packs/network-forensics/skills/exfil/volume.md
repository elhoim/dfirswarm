---
id: exfil/volume
title: Whether data left, and how much
when: The question is exfiltration rather than intrusion.
needs: [capture/what-you-have]
tools: [pcap_summary]
requires_host: [zeek]
---

The whole question is asymmetry. Ordinary use pulls far more than it pushes; a
host that sent four gigabytes and received forty megabytes did something else.

    pcap_summary  gives bytes each way per conversation
    zeek conn.log orig_bytes and resp_bytes, per session, over a whole capture

Work it in this order:

1. **Rank outbound volume by internal host**, over the whole period. The top of
   that list is where the answer is, and it is usually one machine.
2. **Then by destination**, for that host. A single destination taking most of
   it is a transfer; many destinations sharing it is sync software or a backup.
3. **Then by time.** Exfiltration is usually a few sessions in a window, not a
   steady trickle. Put those windows against the host timeline.

Routes people forget: a cloud sync client, which is legitimate software with a
legitimate certificate; webmail with attachments; an HTTPS POST to a paste site;
DNS tunnelling, which is slow and shows as query volume rather than byte volume;
ICMP payloads; and a scheduled upload over SFTP that the estate set up years ago
and nobody remembers.

**Compressed and encrypted first.** An archive made on the host before the
transfer means the byte count on the wire understates what left. Look for the
staging file on disk — see `filesystem/deleted` in the Windows pack — and quote
its uncompressed size as well.

**What a capture cannot tell you is what the data was**, unless it was in the
clear. "4.1 GB was sent to X between 02:10 and 02:40" is a finding.
"The customer database was exfiltrated" needs the staging file, its contents, or
a reconstructed session — and if you do not have one, say which.
