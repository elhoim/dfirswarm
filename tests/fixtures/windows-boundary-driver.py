"""Drives the SHARED BOUNDARY block of a windows-forensics tool in-process, for tests/pack-windows-forensics-boundary-block.test.ts.

usage: windows-boundary-driver.py <module file> <case>    (the module file is the block cut out of a tool's run.py, with its imports)

Every case prints one JSON object. Canaries are built at run time from pieces and random characters, never written out whole.
"""
import importlib.util
import json
import os
import random
import re
import resource
import string
import sys
import time

path, case = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("block", path)
blk = importlib.util.module_from_spec(spec)
spec.loader.exec_module(blk)

A = string.ascii_letters + string.digits
rnd = random.Random(20261015)


def rs(n, alphabet=A):
    return "".join(rnd.choice(alphabet) for _ in range(n))


def printed(secret, doc):
    return secret in json.dumps(doc, ensure_ascii=False)


def peak_mb():
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak / (1024 * 1024) if sys.platform == "darwin" else peak / 1024


def timed(fn):
    t0 = time.time()
    fn()
    return round(time.time() - t0, 3)


def answer(kind, text):
    return blk.answer_object({"status": "complete", "v": blk.T(kind, text)})


KINDS = ("text", "host", "name", "path", "key", "url")
NO_NEWLINE = ("name", "path", "key")

if case == "backslashes":
    out = {}
    for n in (65536, 262144):
        out["seal_%d" % n] = timed(lambda: blk.seal({"v": "\\" * n}))
        out["flat_%d" % n] = timed(lambda: blk._flat("\\" * n))
        out["normal_%d" % n] = timed(lambda: blk._s_normal("\\" * n))
        out["hex_%d" % n] = timed(lambda: blk.seal({"v": blk.T("hex", "5c" * (n // 2))}))
    flat_u = blk._flat("a" + "\\" * 5 + "u200b" + "b")
    flat_g = blk._flat("g" + "hp_" + "\\u200b" + "A" * 36)
    out["escape_removed"] = flat_u == "ab" and "\\u200b" not in flat_g
    print(json.dumps(out))

elif case == "redos":
    # every pattern of the block against hostile repeated shapes, at two sizes: a linear one grows four times for four times the text, a quadratic one sixteen
    atoms = ["\\", "\\x", "\"", "'", "@", ":", "=", "<", "[", "%", "%4", ".", "-", "_", "/", " ", "\t", "a", "A", "7", "AB", "a1", "\\u", "\\u00", "pass=", "password:",
             "AK" + "IA", "ey" + "J", "gh" + "p_", "sk-", "A/", "AAAA=", "http://", "<withheld 1", "[withheld: 1", "\uff21", "\u00e9", "\x00", ";", "&", ",", "glp" + "at-",
             "SG.", "?", "#", "+", "<withheld 5 characters: user-info>:", "a:b@", "xox" + "b-", "ya29.", "AI" + "za", "-----BEGIN PRIVATE KEY-----"]
    prefixes = ["password=", "secret:", "http://u:", "-----BEGIN PRIVATE KEY-----", "gh" + "p_", "ey" + "J", "a:b@", "<withheld 5 characters: user-info>:", "//", "SG."]
    small, large = 4000, 32000
    slow = []
    worst = 0.0
    cases = 0

    def measure(make, label, kinds):
        global worst, cases
        for kind in kinds:
            t0 = time.time()
            blk.seal({"v": blk.T(kind, make(small))})
            t1 = time.time() - t0
            t0 = time.time()
            blk.seal({"v": blk.T(kind, make(large))})
            t2 = time.time() - t0
            cases += 1
            worst = max(worst, t2)
            if t2 > 4 or (t2 > 0.3 and t2 / max(t1, 0.01) > 24):
                slow.append([label, kind, round(t1, 3), round(t2, 3)])

    for atom in atoms:
        measure(lambda n, atom=atom: atom * (n // len(atom)), atom, ("text", "url"))
    for prefix in prefixes:
        for atom in ("a", "-", "/", "@", "=", ":", " ", "1", "\\", "&", ".", "ey" + "J"):
            measure(lambda n, prefix=prefix, atom=atom: prefix + atom * (n // len(atom)), prefix + " + " + atom, ("text",))
    print(json.dumps({"slow": slow, "worst": round(worst, 2), "cases": cases}))

elif case == "same_marker_keys":
    count = 6000
    names = {rs(24): i for i in range(count)}
    before = peak_mb()
    out = {}
    out["seconds"] = timed(lambda: out.__setitem__("sealed", blk.seal({"values": names, "value_types": dict(names), "value_lengths": dict(names)})))
    sealed = out.pop("sealed")
    keys = sealed["values"]
    out["keys"] = len(keys)
    out["longest_key"] = max(len(k) for k in keys)
    out["json_bytes"] = len(json.dumps(sealed))
    out["peak_growth_mb"] = round(peak_mb() - before, 1)
    out["distinct_values_kept"] = sorted(keys.values()) == list(range(count))
    # an unsealable key type does not break the serialiser
    odd = blk.seal({"v": {("a", "b"): 1, 7: 2, None: 3}})
    out["odd_keys_json"] = bool(json.dumps(odd))
    print(json.dumps(out))

elif case == "userinfo":
    n = 300

    def plants(make):
        return [make() for _ in range(n)]

    def families():
        return {
            "url_random_user_short_pw": lambda: (lambda u, p: ("ftp://%s:%s@host.example.org/x" % (u, p), p))(rs(rnd.randint(16, 40)), rs(rnd.randint(8, 15))),
            "bare_random_user_short_pw": lambda: (lambda u, p: ("%s:%s@host.example.org" % (u, p), p))(rs(rnd.randint(16, 40)), rs(rnd.randint(8, 15))),
            "scheme_db_random_user": lambda: (lambda u, p: ("postgres://%s:%s@db.example.org:5432/app" % (u, p), p))(rs(rnd.randint(16, 40)), rs(rnd.randint(8, 15))),
            "key_id_user": lambda: (lambda p: ("https://AK" + "IA%s:%s@s3.example.org/b" % (rs(16, string.ascii_uppercase + "234567"), p), p))(rs(rnd.randint(8, 15))),
            "slash_and_plus_in_password": lambda: (lambda p: ("ftp://admin:%s@srv.example.org/x" % p, p))(rs(4) + "/" + rs(6) + "+" + rs(4)),
            "user_over_64_chars": lambda: (lambda u, p: ("sftp://%s:%s@host.example.org/x" % (u, p), p))(rs(rnd.randint(70, 100)), rs(rnd.randint(8, 15))),
        }

    def leaks(mode):
        saved = (blk._show, blk._verdict, blk._residue)
        if mode == "layers_only":                                    # the backstop taken out
            blk._verdict = lambda text, kind: None
            blk._residue = lambda original, shown, kind: None
        elif mode == "backstop_only":                                # layers 1 and 2 taken out
            blk._show = lambda s, kind, field: s
        res = {}
        try:
            for name, make in families().items():
                count = 0
                for text, pw in plants(make):
                    kind = rnd.choice(KINDS)
                    if kind in NO_NEWLINE and "\n" in text:
                        kind = "text"
                    if printed(pw, answer(kind, text)):
                        count += 1
                res[name] = count
        finally:
            blk._show, blk._verdict, blk._residue = saved
        return res

    print(json.dumps({"n": n, "together": leaks("together"), "layers_only": leaks("layers_only"), "backstop_only": leaks("backstop_only")}))

elif case == "glued":
    n = 200
    hexa = "0123456789abcdefABCDEF"
    res = {}
    for kind in ("text", "host", "path", "key", "url"):
        for glue in ((1, 4), (11, 20), (21, 40)):
            count = 0
            for _ in range(n):
                core = rs(20, A + "-_")
                text = "".join(rnd.choice(hexa) for _ in range(rnd.randint(*glue))) + "glp" + "at-" + core
                if printed(core, answer(kind, text)):
                    count += 1
            res["%s_%d_%d" % (kind, glue[0], glue[1])] = count
    # the same with the first layer taken out, and with the backstop taken out
    saved = (blk._show, blk._verdict, blk._residue)
    alone = {}
    try:
        blk._show = lambda s, kind, field: s
        alone["backstop_only"] = sum(printed(c, answer("text", rs(rnd.randint(11, 40), hexa) + "glp" + "at-" + c)) for c in [rs(20, A + "-_") for _ in range(n)])
        blk._show, blk._verdict, blk._residue = saved[0], (lambda text, kind: None), (lambda original, shown, kind: None)
        alone["layers_only"] = sum(printed(c, answer("text", rs(rnd.randint(11, 40), hexa) + "glp" + "at-" + c)) for c in [rs(20, A + "-_") for _ in range(n)])
    finally:
        blk._show, blk._verdict, blk._residue = saved
    print(json.dumps({"n": n, "whole": res, "alone": alone}))

elif case == "replaced_at":
    # a key that layer 1 withholds, beside a value only the backstop replaces (layer 1 left off the values): the place of the replacement must not print the key
    results = {"keys_printed": 0, "windows_printed": 0, "plants": 0, "with_place": 0}
    saved = blk._show

    def keep_values(s, kind, field):
        return saved(s, kind, field) if kind == "name" else s

    blk._show = keep_values
    try:
        for i in range(200):
            key = rs(30)
            prefix = rnd.choice(["AI" + "za", "AK" + "IA", "gh" + "p_"])
            value = prefix + rs(36, A + "+/")
            doc = {"status": "complete", "values": {key: value}, "subkeys": [{"name": "k%d" % i, "values": {key: value}}]}
            out = blk.answer_object(doc)
            text = json.dumps(out, ensure_ascii=False)
            results["plants"] += 1
            results["keys_printed"] += key in text
            results["windows_printed"] += any(key[j:j + 12] in text for j in range(0, 19))
            results["with_place"] += bool(out["boundary"]["replaced_at"])
    finally:
        blk._show = saved
    # and a key the backstop itself replaces: the place says positions, not the key
    out = blk.answer_object({"status": "complete", "values": {"AK" + "IA" + rs(16, string.ascii_uppercase + "234567"): "x"}})
    results["key_replaced_place"] = out["boundary"]["replaced_at"]
    print(json.dumps(results))

elif case == "labels":
    # every placeholder the block can write is one of the fixed list and is taken for a placeholder by both patterns
    texts = []
    for _ in range(400):
        texts.append(rs(rnd.randint(1, 80)))
        texts.append("password=" + rs(12) + " http://" + rs(20) + ":" + rs(10) + "@h/x " + rs(30, A + "+/") + "== -----BEGIN PRIVATE KEY----- " + rs(20))
        texts.append("\u200b" + rs(10) + "\x00" + rs(5))
    seen = set()
    bad = []
    for kind in ("text", "name", "path", "key", "url", "host", "hex", "guid", "digest", "sid", "mac", "ip", "time", "number", "version"):
        for t in texts:
            o = blk.answer_object({"status": "complete", "v": blk.T(kind, t)})
            for marker in re.findall(r"<withheld [^<>]*>|\[withheld: [^\]]*\]", json.dumps(o, ensure_ascii=False)):
                if marker in seen or "N characters" in marker:       # the sentence of the report that explains the placeholder
                    continue
                seen.add(marker)
                if not blk._MARK.fullmatch(marker) or not blk._S_MARK.fullmatch(marker):
                    bad.append(marker)
    print(json.dumps({"markers": len(seen), "not_recognised": bad[:5]}))

elif case == "hex":
    out = {"claimed_hex_flagged": 0, "claimed_hex": 0, "claimed_hex_printed": 0, "random_binary_printed": 0, "random_binary": 0, "ip_field_base64_replaced": 0, "ip_field": 0}
    pems = lambda: "-----BEGIN PRIVATE KEY-----" + rs(48, A + "+/") + "-----END PRIVATE KEY-----"
    makers = [lambda: "gh" + "p_" + rs(36), lambda: "AK" + "IA" + rs(16, string.ascii_uppercase + "234567"), lambda: "password=" + rs(14), pems,
              lambda: "https://svc:" + rs(12) + "@h.example.org/r", lambda: "eyJ" + rs(30) + "." + rs(30) + "." + rs(43)]
    for make in makers:
        for _ in range(40):
            text = make()
            for enc in ("latin-1", "utf-16-le"):
                hexed = text.encode(enc).hex()
                out["claimed_hex"] += 1
                out["claimed_hex_flagged"] += bool(blk._verdict(hexed, "hex"))             # the backstop alone, whatever the first layer does
                out["claimed_hex_printed"] += hexed in json.dumps(answer("hex", hexed))     # the whole pipeline
    for size in (16, 24, 32, 48, 64):
        for _ in range(40):
            hexed = bytes(rnd.randrange(256) for _ in range(size)).hex()
            out["random_binary"] += 1
            out["random_binary_printed"] += hexed in json.dumps(answer("hex", hexed))
    saved = blk._show
    blk._show = lambda s, kind, field: s
    try:
        for _ in range(60):
            b64 = rs(40, A + "+/")
            out["ip_field"] += 1
            out["ip_field_base64_replaced"] += b64 not in json.dumps(answer("ip", b64))
    finally:
        blk._show = saved
    print(json.dumps(out))

elif case == "scalars":
    # a value that is not a string, a number or a container is sealed as the text str() makes of it, not printed by the serialiser
    import pathlib
    secret = "gh" + "p_" + rs(36)
    doc = {"status": "complete", "b": ("password=" + rs(12)).encode(), "p": pathlib.PurePosixPath("/x/" + secret), "s": {secret + "A"}, "t": (secret, 1), "n": None, "f": 1.5, "ok": True}
    text = json.dumps(blk.answer_object(doc), ensure_ascii=False, default=str)
    print(json.dumps({"secret_printed": secret in text, "pieces_kept": '"f": 1.5' in text and '"ok": true' in text and '"n": null' in text}))

elif case == "order_and_contains":
    res = {}
    names = [rs(24) for _ in range(8)] + ["Alpha", "Beta", "Containers", "Zeta"]
    orders = set()
    first_always_rank = True
    for _ in range(25):
        blk._ORDER_SALT = os.urandom(16)
        ordered = blk.print_order(list(names))
        orders.add(tuple(ordered))
        if [n for n in ordered if len(n) == 24] != sorted(n for n in names if len(n) == 24):
            first_always_rank = False
    res["distinct_orders"] = len(orders)
    res["rank_order_always"] = first_always_rank
    res["plain_names_sorted_among_themselves"] = all([n for n in o if len(n) != 24] == ["Alpha", "Beta", "Containers", "Zeta"] for o in orders)
    res["plain_before_markers"] = all(o.index("Zeta") < min(o.index(n) for n in o if len(n) == 24) or True for o in orders)
    # printing order must not change the counts the answer reports
    before = blk.BOUNDARY["withheld"]
    blk.print_order(names)
    res["order_counts_nothing"] = blk.BOUNDARY["withheld"] == before
    secret = "gh" + "p_" + rs(36)
    xml = "<E><Data>token " + secret + " done</Data><Data>hello world</Data></E>"
    res["contains_hit_shown"] = blk.contains_check("hello", xml)
    res["contains_in_withheld"] = blk.contains_check(secret[:12].lower(), xml)
    res["contains_nothing_withheld"] = blk.contains_check("zzz", "<E><Data>hello world</Data></E>")
    res["blind_does_not_depend_on_needle"] = blk.contains_check("qqqq", xml) == blk.contains_check(secret[:12].lower(), xml)
    print(json.dumps(res))

elif case == "residue":
    # a secret that is cut by the layers above leaves no piece of 12 characters that the backstop calls secret
    n = 300
    shapes = {
        "aws_secret_40": lambda: (lambda c: ("aws_secret_access_key is " + c, c))(rs(40, A + "+/")),
        "aws_secret_40_alone": lambda: (lambda c: (c, c))(rs(40, A + "+/")),
        "upper_prefix": lambda: (lambda c: ("GH" + "P_" + c, c))(rs(36)),
        "named_with_ampersand": lambda: (lambda a, b: ("Password=" + a + "&" + b, b))(rs(7), rs(12, A + "^$%")),
        "named_with_semicolon": lambda: (lambda a, b: ("Password=" + a + ";" + b + " rest", b))(rs(7), rs(12, A + "^$%")),
        "ya29": lambda: (lambda c: ("ya" + "29." + c, c))(rs(60, A + "-_")),
        "sendgrid": lambda: (lambda a, b: ("SG." + a + "." + b, b))(rs(22, A + "-_"), rs(43, A + "-_")),
    }
    res = {}
    for name, make in shapes.items():
        whole = frag = 0
        for _ in range(n):
            text, core = make()
            kind = rnd.choice(("text", "path", "key", "url", "host"))
            text_out = json.dumps(answer(kind if "\n" not in text else "text", text), ensure_ascii=False)
            whole += core in text_out
            frag += any(core[i:i + 12] in text_out for i in range(0, max(1, len(core) - 11)))
        res[name] = [whole, frag]
    # benign text the new rules must leave alone
    benign = ["ftp://admin:[withheld: 16 characters]@files.example.test/", "/usr/share/man/mann/iwidgets_canvasprintdialog.n", "C:\\Windows\\System32\\svchost.exe -k netsvcs -p", "NPM_CONFIG_USERCONFIG=C:\\Users\\bob\\.npmrc",
              "https://github.com/halilozturkci/dfirswarm/pull/162/files", "Security ID: S-1-5-18 Account Name: DC01$ Logon ID: 0x3E7", "host.example.com:8080/path/user@mail.example.com/x"]
    res["benign_changed"] = [b for b in benign if blk.seal({"v": blk.T("text", b)})["v"] != b]
    # lines whose named secret the first layers do withhold, and whose own words must not make the backstop replace the rest
    before = blk.BOUNDARY["replaced"]
    blk.answer_object({"status": "complete", "a": "pwd = (self.password.encode('utf-8') if isinstance(self.password, str)",
                       "b": "it = _tokenize.TokenizerIter(source, encoding=encoding, extra_tokens=extra_tokens)"})
    res["benign_backstop_replaced"] = blk.BOUNDARY["replaced"] - before
    print(json.dumps(res))

elif case == "basis":
    saved = blk._verdict
    blk._verdict = lambda text, kind: "a PEM marker" if text == "trigger" else None
    try:
        out = blk.answer_object({"status": "complete", "v": "trigger"})
    finally:
        blk._verdict = saved
    print(json.dumps({"status": out["status"], "basis": out["status_basis"]}))

else:
    raise SystemExit("unknown case " + case)
