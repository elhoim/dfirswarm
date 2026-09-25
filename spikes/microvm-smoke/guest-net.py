#!/usr/bin/env python3
"""Runs inside the VM. Tries each way out we care about and says what happened.

No proxy variables are involved: this is the path that escaped netguard on
run s83fd (`env -u HTTP_PROXY ... python3 -m pip install`), taken on purpose.
"""
import os
import socket
import urllib.request

TIMEOUT = 4


def attempt(name, fn):
    try:
        detail = fn()
        print(f"OPEN     {name}{': ' + detail if detail else ''}")
    except Exception as e:  # noqa: BLE001 - every failure is the answer here
        print(f"closed   {name}: {type(e).__name__}: {e}")


def resolve(host):
    return lambda: ",".join(sorted({a[4][0] for a in socket.getaddrinfo(host, 443, socket.AF_INET)}))


def tcp(host, port):
    def go():
        with socket.create_connection((host, port), timeout=TIMEOUT) as s:
            return f"connected to {s.getpeername()[0]}"
    return go


def http_get(url):
    def go():
        with urllib.request.urlopen(url, timeout=TIMEOUT) as r:
            return f"HTTP {r.status}, {len(r.read(2048))} bytes"
    return go


def udp_dns(server):
    def go():
        # A bare query for example.com A, sent straight to a public resolver.
        query = bytes.fromhex("abcd01000001000000000000076578616d706c6503636f6d0000010001")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(TIMEOUT)
            s.sendto(query, (server, 53))
            data, _ = s.recvfrom(512)
            rcode = data[3] & 0x0F
            answers = int.from_bytes(data[6:8], "big")
            names = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN", 5: "REFUSED"}
            return f"{len(data)}-byte answer, rcode {names.get(rcode, rcode)}, {answers} answer records"
    return go


print(f"== interfaces: {', '.join(sorted(os.listdir('/sys/class/net')))}")
attempt("resolve deb.debian.org", resolve("deb.debian.org"))
attempt("resolve example.com", resolve("example.com"))
attempt("resolve a made-up subdomain (DNS exfil)", resolve("exfil-7f3a9c.example.com"))
attempt("tcp deb.debian.org:80 by name", tcp("deb.debian.org", 80))
attempt("tcp example.com:443 by name", tcp("example.com", 443))
attempt("tcp 1.1.1.1:443 hard-coded IP", tcp("1.1.1.1", 443))
attempt("udp 8.8.8.8:53 direct DNS", udp_dns("8.8.8.8"))
attempt("http deb.debian.org Release", http_get("http://deb.debian.org/debian/dists/bookworm/Release"))
attempt("https example.com", http_get("https://example.com/"))
attempt("LAN 192.168.1.1:80", tcp("192.168.1.1", 80))
attempt("cloud metadata 169.254.169.254:80", tcp("169.254.169.254", 80))
attempt("host.microsandbox.internal:22", tcp("host.microsandbox.internal", 22))
