/**
 * network-forensics: pcap_extract exports protocol objects with tshark and indexes them.
 *
 * tshark is not on every machine these suites run on, so a stand-in program prints what tshark's manual says
 * it prints: `--version` and `--export-objects help` for the build, `--export-objects <protocol>,<dir>` writing
 * object files into the directory, `-T fields -E header=y ...` writing a tab-separated listing whose last
 * column is the hex of the HTTP entity body. That proves the wrapper's own logic (receipts, deadline,
 * association, withholding), not tshark's: whether a real build accepts an exporter name, honours `-Y` on
 * export, or prints `http.file_data` for every body is a thing to check on the build the evidence is read with.
 *
 * What is held here: each exported object is tied to a frame and a stream where its content matches exactly one
 * response body, and is marked ambiguous or unmapped otherwise; a first pass that runs out of time still leaves
 * an index and a partial receipt; an exporter the build does not list is refused by name; a name or a request
 * URI shaped like a credential, and a short object's digest, are withheld from everything the answer names, and
 * the values behind them are written only to a 0600 file in a job; the output directory is private.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { EXTRACT, asJob, body, drop, everythingUnder, exists, filesUnder, frameTcp4, pcapClassic, refused, stub, tool, TCP, withCwd } from "./pack-network-harness.ts";
import type { Json } from "./pack-network-harness.ts";

const sha = (b: Buffer | string): string => createHash("sha256").update(b).digest("hex");
const BODY_A = Buffer.from("A".repeat(200));
const BODY_B = Buffer.from("B".repeat(300));
const SHORT = Buffer.from("tiny-object");

const FIELDS = ["frame.number", "frame.time_epoch", "tcp.stream", "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "http.host", "http.response_for.uri", "http.file_data"];

/** The stand-in: reads what to do from $STUB_DIR, and records every call in $STUB_LOG. */
const TSHARK = `#!/bin/sh
printf '%s\\n' "$*" >> "$STUB_LOG"
spec=""; fields=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) printf 'TShark (Wireshark) 4.2.0 (stand-in)\\n'; exit 0;;
    --export-objects) spec="$2"; shift;;
    -T) fields=yes;;
  esac
  shift
done
if [ "$spec" = help ]; then
  { printf 'tshark: The available export object types for the "--export-objects" option are:\\n'; sed 's/^/    /' "$STUB_DIR/exporters.txt"; } >&2
  exit 0
fi
if [ -n "$spec" ]; then
  proto="\${spec%%,*}"; dest="\${spec#*,}"
  [ -f "$STUB_DIR/sleep-$proto" ] && exec sleep "$(cat "$STUB_DIR/sleep-$proto")"
  if [ -f "$STUB_DIR/spawn-$proto" ]; then sleep 60 & echo $! > "$STUB_DIR/child.pid"; echo started > "$STUB_DIR/started"; wait; fi
  [ -d "$STUB_DIR/export/$proto" ] && cp -R "$STUB_DIR/export/$proto/." "$dest/"
  if [ -f "$STUB_DIR/exit-$proto" ]; then echo "tshark: stand-in failing on request" >&2; exit "$(cat "$STUB_DIR/exit-$proto")"; fi
  exit 0
fi
if [ -n "$fields" ]; then cat "$STUB_DIR/assoc.tsv"; exit 0; fi
exit 0
`;

async function stage(cwd: string, bin: string, o: { exporters?: string[]; export?: Record<string, Record<string, Buffer | string>>; assoc?: string[][]; assocRaw?: string; sleeps?: Record<string, number>; exits?: Record<string, number>; spawns?: string[] }): Promise<{ log: string; dir: string }> {
  const dir = join(cwd, "stub");
  await rm(dir, { recursive: true, force: true });
  await mkdir(dir, { recursive: true });
  await stub(bin, "tshark", TSHARK);
  await writeFile(join(dir, "exporters.txt"), (o.exporters ?? ["dicom", "http", "imf", "smb", "tftp"]).join("\n") + "\n");
  for (const [proto, files] of Object.entries(o.export ?? {})) {
    for (const [name, data] of Object.entries(files)) {
      await mkdir(join(dir, "export", proto, name, ".."), { recursive: true });
      await writeFile(join(dir, "export", proto, name), data);
    }
  }
  for (const [proto, s] of Object.entries(o.sleeps ?? {})) await writeFile(join(dir, `sleep-${proto}`), String(s));
  for (const [proto, c] of Object.entries(o.exits ?? {})) await writeFile(join(dir, `exit-${proto}`), String(c));
  for (const proto of o.spawns ?? []) await writeFile(join(dir, `spawn-${proto}`), "1");
  const rows = o.assoc ?? [];
  await writeFile(join(dir, "assoc.tsv"), o.assocRaw ?? [FIELDS.join("\t"), ...rows.map((r) => r.join("\t"))].join("\n") + "\n");
  const log = join(cwd, "tshark-calls.txt");
  await writeFile(log, "");
  return { log, dir };
}

const env = (cwd: string, extra: Record<string, string> = {}) => ({ STUB_DIR: join(cwd, "stub"), STUB_LOG: join(cwd, "tshark-calls.txt"), ...extra });

async function capture(cwd: string): Promise<string> {
  return drop(cwd, "work/c.pcap", pcapClassic([{ sec: 1, frame: frameTcp4({ src: "203.0.113.7", dst: "10.0.0.5", sport: 80, dport: 50000, flags: TCP.ACK }) }]));
}

function row(frame: number, stream: number, uri: string, data: Buffer, time = "1700000000.123456789"): string[] {
  return [String(frame), time, String(stream), "203.0.113.7", "", "10.0.0.5", "", "files.example.test", uri, data.toString("hex")];
}

async function index(cwd: string, dir: string): Promise<Json[]> {
  const lines = (await readFile(join(cwd, dir, "index.tsv"), "utf8")).trimEnd().split("\n");
  const head = lines[0].split("\t");
  return lines.slice(1).map((l) => Object.fromEntries(l.split("\t").map((v, i) => [head[i], v])));
}

test("an exported object is tied to the frame and stream whose body it matches; a body returned twice is ambiguous; one with no match is unmapped", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, {
      export: { http: { "a.html": BODY_A, "b.bin": BODY_B, "c.txt": "C".repeat(150), "d.txt": "D".repeat(160) } },
      assoc: [row(7, 0, "/a.html", BODY_A), row(12, 1, "/b.bin", BODY_B), row(20, 2, "/d.txt", Buffer.from("D".repeat(160))), row(21, 3, "/d-again.txt", Buffer.from("D".repeat(160)))],
    });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin));
    assert.equal(out.objects, 4);
    assert.equal(out.ok, true);
    const rows = await index(cwd, "work/x");
    const by = Object.fromEntries(rows.map((r) => [r.name, r]));
    assert.equal(by["a.html"].association, "matched_by_content");
    assert.equal(by["a.html"].frame, "7");
    assert.equal(by["a.html"].stream, "0");
    assert.equal(by["a.html"].time_utc, "2023-11-14T22:13:20.123456789Z");
    assert.equal(by["a.html"].src, "203.0.113.7");
    assert.equal(by["b.bin"].frame, "12");
    assert.equal(by["c.txt"].association, "unmapped", "no response body matched this object");
    assert.equal(by["c.txt"].frame, "");
    assert.equal(by["d.txt"].association, "ambiguous");
    assert.equal(by["d.txt"].frame, "", "no single frame is claimed");
    assert.match(by["d.txt"].frames, /20/);
    assert.match(by["d.txt"].frames, /21/);
    // Every row has a frame and stream, or says it has none.
    for (const r of rows) assert.ok(r.frame !== "" || ["unmapped", "ambiguous"].includes(r.association), JSON.stringify(r));
    assert.equal(by["a.html"].sha256, sha(BODY_A));
    assert.equal(out.association.matched_by_content, 2);
    assert.equal(out.association.unmapped, 1);
    assert.equal(out.association.ambiguous, 1);
  });
});

test("a protocol with no association method is unmapped, and says why", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { export: { tftp: { "boot.img": BODY_B } } });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["tftp"] }, env(cwd), bin));
    const rows = await index(cwd, "work/x");
    assert.equal(rows[0].association, "unmapped");
    assert.match(rows[0].association_reason, /no content-to-frame association/);
    assert.equal(out.association.unmapped, 1);
  });
});

test("the build, the filter and the exporters it lists are recorded; a name it does not list is refused before anything runs", async () => {
  await withCwd(async (cwd, bin) => {
    const { log } = await stage(cwd, bin, { exporters: ["http", "tftp"], export: { http: { "a.html": BODY_A } }, assoc: [row(3, 0, "/a.html", BODY_A)] });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", display_filter: "ip.addr == 10.0.0.5" }, env(cwd), bin));
    assert.match(out.tshark_version, /4\.2\.0/);
    assert.equal(out.display_filter, "ip.addr == 10.0.0.5");
    assert.deepEqual(out.exporters_supported, ["http", "tftp"]);
    // The default list names smb, smb2 and imf; this build lists none of them. They are skipped, and said.
    assert.deepEqual(out.protocols_skipped_unsupported.sort(), ["imf", "smb", "smb2"]);
    assert.deepEqual(out.runs.map((r: Json) => r.protocol), ["http", "tftp"]);
    assert.match(out.note, /-Y/);
    // An explicit name the build does not list is a refusal, and no export pass ran.
    await writeFile(log, "");
    const err = refused(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/y", protocols: ["http", "smb3"] }, env(cwd), bin));
    assert.match(err.error, /smb3/);
    assert.deepEqual(err.exporters_supported, ["http", "tftp"]);
    assert.doesNotMatch(await readFile(log, "utf8"), /--export-objects http,/);
    assert.equal(await exists(join(cwd, "work/y")), false, "nothing was written for a refused request");
  });
});

test("a build whose exporter list cannot be read is said, and the passes still run and fail loudly on their own", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { exporters: [], export: { http: { "a.html": BODY_A } }, exits: { smb2: 2 } });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin));
    assert.equal(out.exporters_discovered, false);
    assert.equal(out.ok, true);
  });
});

test("a first pass that runs out of time leaves an index and a partial receipt, and the passes after it are not attempted", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { sleeps: { http: 30 }, export: { smb: { "x.dat": BODY_B } } });
    const started = Date.now();
    const result = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http", "smb"], timeout_seconds: 2 }, env(cwd), bin);
    assert.ok(Date.now() - started < 20_000, "the deadline ended the pass");
    assert.notEqual(result.code, 0);
    const out = JSON.parse(result.stdout);
    assert.equal(out.ok, false);
    const byProto = Object.fromEntries(out.runs.map((r: Json) => [r.protocol, r]));
    assert.equal(byProto.http.status, "timed_out");
    assert.equal(byProto.smb.status, "not_attempted");
    assert.equal(byProto.smb.reason, "the shared deadline was used up by an earlier pass");
    assert.ok(await exists(join(cwd, "work/x/index.tsv")), "the index exists");
    const receipt = JSON.parse(await readFile(join(cwd, "work/x/receipt.json"), "utf8"));
    assert.equal(receipt.status, "partial");
    assert.equal(receipt.runs.find((r: Json) => r.protocol === "http").status, "timed_out");
  });
});

test("a pass that fails keeps its whole diagnostic, and the objects of the others are still indexed", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { exits: { http: 7 }, export: { smb: { "x.dat": BODY_B } } });
    const result = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http", "smb"] }, env(cwd), bin);
    assert.notEqual(result.code, 0);
    const out = JSON.parse(result.stdout);
    assert.equal(out.ok, false);
    assert.equal(out.errors[0].exit_code, 7);
    assert.ok(out.errors[0].stderr);
    assert.equal(out.objects, 1);
    assert.match(await readFile(join(cwd, "work/x/_logs/http.stderr"), "utf8"), /stand-in failing/);
  });
});

const NAME_TOKEN = "Zk9mQ2xW7vB3nL8pR4tY6wD1sFgHjK"; // an object named like a token
const URI_TOKEN = "SuperSecretToken987";
const USER_PASS = "alice:PassWord1234";

test("a credential-shaped name, a URI's user-info and query values are withheld from everything the answer names; a short object's digest is not written", async () => {
  await withCwd(async (cwd, bin) => {
    const uri = `http://${USER_PASS}@files.example.test/get/${NAME_TOKEN}?token=${URI_TOKEN}&n=2`;
    await stage(cwd, bin, {
      export: { http: { [`${NAME_TOKEN}.bin`]: BODY_A, "tiny.txt": SHORT, "report.pdf": BODY_B } },
      assoc: [row(5, 0, uri, BODY_A), row(6, 1, "/report.pdf", BODY_B), row(7, 2, "/tiny.txt", SHORT)],
    });
    const result = await asJob(EXTRACT, cwd, { path: await capture(cwd), out_dir: "out/x", protocols: ["http"] }, bin, env(cwd));
    const out = body(result);
    const everything = await everythingUnder(cwd, result.stdout, ["out"]);
    for (const secret of [NAME_TOKEN, URI_TOKEN, "PassWord1234", sha(SHORT)]) {
      assert.equal(everything.includes(secret), false, `${secret} reached the answer or a file it names`);
    }
    // The object is still there, under a name that is no secret, and the row says so.
    const rows = await index(cwd, "out/x");
    const renamed = rows.find((r) => r.name.startsWith("<name withheld"));
    assert.ok(renamed, JSON.stringify(rows));
    assert.match(renamed.path, /^http\/withheld-000001\.bin$/);
    assert.ok(await exists(join(cwd, "out/x", renamed.path)));
    assert.equal(renamed.frame, "5", "the association was made on the content, before the name was withheld");
    assert.match(renamed.request_uri, /^http:\/\/<userinfo withheld \d+ characters>@files\.example\.test\//);
    assert.match(renamed.request_uri, /token=<withheld \d+ characters>/);
    const tiny = rows.find((r) => r.name === "tiny.txt");
    assert.equal(tiny.sha256, "");
    assert.match(tiny.sha256_withheld, /shorter than 128 bytes/);
    assert.equal(rows.find((r) => r.name === "report.pdf").sha256, sha(BODY_B));
    assert.equal(out.names_withheld >= 1, true);
    // The directory and the objects are private.
    assert.equal(((await stat(join(cwd, "out/x"))).mode & 0o777).toString(8), "700");
    assert.equal(((await stat(join(cwd, "out/x/http/report.pdf"))).mode & 0o777).toString(8), "600");
    assert.equal(out.out_dir_contains_secret_values, true);
    assert.match(out.out_dir_note, /secret_output: true/);
  });
});

test("write_values puts the real names and URIs in one 0600 file under $OUT, and is refused outside a job; a second run in the same job is refused, not crashed, and leaves the first file alone", async () => {
  await withCwd(async (cwd, bin) => {
    const uri = `http://${USER_PASS}@files.example.test/get?token=${URI_TOKEN}`;
    await stage(cwd, bin, { export: { http: { [`${NAME_TOKEN}.bin`]: BODY_A } }, assoc: [row(5, 0, uri, BODY_A)] });
    const args = { path: await capture(cwd), out_dir: "work/plain", protocols: ["http"], write_values: true };
    const outside = refused(await tool(EXTRACT, cwd, args, env(cwd), bin));
    assert.match(outside.error, /outside a job/);
    assert.equal(await exists(join(cwd, "work/plain")), false, "nothing was written");
    // In a job.
    const first = body(await asJob(EXTRACT, cwd, { ...args, out_dir: "out/one" }, bin, env(cwd)));
    assert.equal(first.secret_values.written, 1);
    const file = join(cwd, "out", "pcap-extract-values.jsonl");
    assert.equal(((await stat(file)).mode & 0o777).toString(8), "600");
    const rows = (await readFile(file, "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    assert.equal(rows.length, 1);
    assert.match(rows[0].value, new RegExp(NAME_TOKEN));
    assert.equal(rows[0].request_uri, uri);
    assert.match(rows[0].finding_id, /^O\d{6}$/);
    const before = await readFile(file, "utf8");
    // Same job output, a second run: refused in JSON, the first values file untouched.
    const second = refused(await asJob(EXTRACT, cwd, { ...args, out_dir: "out/two" }, bin, env(cwd)));
    assert.match(second.error, /already exists/);
    assert.equal(await readFile(file, "utf8"), before);
    // And a run with nothing to withhold leaves an empty 0600 file and says written: 0.
    await stage(cwd, bin, { export: { http: { "plain.txt": BODY_A } }, assoc: [] });
    const empty = body(await asJob(EXTRACT, cwd, { ...args, out_dir: "out3/x" }, bin, env(cwd), "out3"));
    assert.equal(empty.secret_values.written, 0);
    assert.equal((await stat(join(cwd, "out3", "pcap-extract-values.jsonl"))).size, 0);
  });
});

test("in a job out_dir must be under $OUT, and an output place that cannot be written is a JSON error, not a traceback", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } } });
    const outside = refused(await asJob(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/elsewhere", protocols: ["http"] }, bin, env(cwd)));
    assert.match(outside.error, /\$OUT/);
    // A directory that exists and cannot be written (root writes anywhere, so there is nothing to refuse there).
    if (typeof process.getuid === "function" && process.getuid() === 0) return;
    await mkdir(join(cwd, "work/locked"), { recursive: true });
    await chmod(join(cwd, "work/locked"), 0o555);
    try {
      const blocked = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/locked/x", protocols: ["http"] }, env(cwd), bin);
      assert.notEqual(blocked.code, 0);
      assert.doesNotMatch(blocked.stderr, /Traceback/);
      assert.match(JSON.parse(blocked.stdout).error, /could not be (created|written)/);
    } finally {
      await chmod(join(cwd, "work/locked"), 0o755);
    }
  });
});

test("a second run into another directory never replaces the first run's index", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } }, assoc: [row(3, 0, "/a.html", BODY_A)] });
    body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/one", protocols: ["http"] }, env(cwd), bin));
    const first = await readFile(join(cwd, "work/one/index.tsv"), "utf8");
    const again = refused(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/one", protocols: ["http"] }, env(cwd), bin));
    assert.match(again.error, /already holds files/);
    assert.equal(await readFile(join(cwd, "work/one/index.tsv"), "utf8"), first);
    assert.deepEqual((await filesUnder(join(cwd, "work/one"))).filter((f) => f.endsWith(".tmp")), []);
  });
});

test("a row that cannot be read, or a header that is not the fields asked for, means no frame is claimed for any object, and the run says so", async () => {
  await withCwd(async (cwd, bin) => {
    const good = row(7, 0, "/a.html", BODY_A).join("\t");
    const damaged = [...row(8, 1, "/b.bin", BODY_B).slice(0, 9), "ZZ-not-hex"].join("\t");
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } }, assocRaw: [FIELDS.join("\t"), good, damaged].join("\n") + "\n" });
    const result = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin);
    assert.notEqual(result.code, 0);
    const out = JSON.parse(result.stdout);
    assert.equal(out.ok, false);
    assert.equal(out.association_pass.status, "incomplete");
    assert.equal(out.association_pass.rows_unreadable, 1);
    assert.deepEqual(out.association_pass.first_unreadable_lines, [3], "the line number counts the header");
    const rows = await index(cwd, "work/x");
    assert.equal(rows[0].association, "failed");
    assert.equal(rows[0].frame, "", "a claim from a partial listing could be wrong, so none is made");
    assert.match(rows[0].association_reason, /no frame is claimed/);
    // The header is the contract: another set of columns means the fields cannot be trusted.
    await stage(cwd, bin, { export: { http: { "a.html": BODY_A } }, assocRaw: ["frame.number\thttp.file_data", good].join("\n") + "\n" });
    const wrong = JSON.parse((await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/y", protocols: ["http"] }, env(cwd), bin)).stdout);
    assert.equal(wrong.association_pass.status, "failed");
    assert.match(wrong.association_pass.reason, /header/);
  });
});

test("a body larger than one read of the pipe is hashed as it goes by and still matched, and nothing holding a body is written", async () => {
  await withCwd(async (cwd, bin) => {
    const big = randomBytes(3 * 1024 * 1024 + 11);
    await stage(cwd, bin, { export: { http: { "big.bin": big } }, assoc: [row(31, 4, "/big.bin", big)] });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin));
    assert.equal(out.association.matched_by_content, 1);
    const rows = await index(cwd, "work/x");
    assert.equal(rows[0].frame, "31");
    assert.equal(rows[0].sha256, sha(big));
    for (const f of await filesUnder(join(cwd, "work/x"))) {
      assert.ok((await stat(join(cwd, "work/x", f))).size < 4 * 1024 * 1024 + 100 || f.startsWith("http/"), `${f} is larger than an object: a listing was kept`);
    }
    assert.deepEqual((await filesUnder(join(cwd, "work/x"))).filter((f) => /assoc|listing/i.test(f) && !f.startsWith("_logs/")), []);
  });
});

test("a body in many frames is ambiguous with the whole frame list kept in a file; two objects with the same bytes and one frame are ambiguous, not matched", async () => {
  await withCwd(async (cwd, bin) => {
    const many = Array.from({ length: 30 }, (_, i) => row(100 + i, i, `/r${i}`, BODY_A));
    await stage(cwd, bin, {
      export: { http: { "one.bin": BODY_A, "same-a.bin": BODY_B, "same-b.bin": BODY_B } },
      assoc: [...many, row(900, 40, "/b", BODY_B)],
    });
    const out = body(await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }, env(cwd), bin));
    assert.equal(out.association.ambiguous, 3);
    assert.equal(out.association.matched_by_content, 0);
    const rows = await index(cwd, "work/x");
    const one = rows.find((r) => r.name === "one.bin");
    assert.equal(one.frames.split(",").length, 21, "twenty frames and a count of the rest");
    assert.match(one.frames, /\+10 more$/);
    assert.equal(one.frame, "");
    const sets = (await readFile(join(cwd, "work/x/association-candidates.jsonl"), "utf8")).trimEnd().split("\n").map((l) => JSON.parse(l));
    const whole = sets.find((s: Json) => s.frames.length === 30);
    assert.ok(whole, "the whole list of the repeated body is on disk");
    assert.deepEqual(whole.frames.slice(0, 3), [100, 101, 102]);
    assert.match(one.association_reason, /candidate_set S\d{6}/);
    assert.equal(JSON.stringify(sets).includes(sha(BODY_A)), false, "no digest in the candidates file");
  });
});

test("a token-shaped directory name is moved aside too, and a pass's children die with it", async () => {
  await withCwd(async (cwd, bin) => {
    await stage(cwd, bin, { export: { smb: { [`${NAME_TOKEN}/inner.txt`]: BODY_B } } });
    const result = await asJob(EXTRACT, cwd, { path: await capture(cwd), out_dir: "out/x", protocols: ["smb"] }, bin, env(cwd));
    const out = body(result);
    const everything = await everythingUnder(cwd, result.stdout, ["out"]);
    assert.equal(everything.includes(NAME_TOKEN), false);
    const rows = await index(cwd, "out/x");
    assert.match(rows[0].path, /^smb\/withheld-000001\/inner\.txt$/);
    assert.equal(out.names_withheld, 1);
  });
  await withCwd(async (cwd, bin) => {
    const { dir } = await stage(cwd, bin, { spawns: ["http"] });
    const started = Date.now();
    const result = await tool(EXTRACT, cwd, { path: await capture(cwd), out_dir: "work/x", protocols: ["http"], timeout_seconds: 2 }, env(cwd), bin);
    assert.ok(Date.now() - started < 20_000);
    assert.notEqual(result.code, 0);
    const pid = Number((await readFile(join(dir, "child.pid"), "utf8")).trim());
    assert.ok(pid > 1);
    await new Promise((r) => setTimeout(r, 300));
    assert.throws(() => process.kill(pid, 0), /ESRCH/, "the sleeper the pass started is gone");
  });
});

test("a stop signal kills the pass and leaves a receipt that says it was interrupted", async () => {
  await withCwd(async (cwd, bin) => {
    const { dir } = await stage(cwd, bin, { spawns: ["http"] });
    await writeFile(join(cwd, "args.json"), JSON.stringify({ path: await capture(cwd), out_dir: "work/x", protocols: ["http"] }));
    const child = spawn("python3", [EXTRACT], { cwd, env: { ...process.env, AGENT_ID: "s1", PATH: `${bin}:${process.env.PATH}`, ...env(cwd) } });
    const stdout: Buffer[] = [];
    child.stdout.on("data", (c: Buffer) => stdout.push(c));
    child.stdin.end(await readFile(join(cwd, "args.json")));
    for (let i = 0; i < 100 && !(await exists(join(dir, "started"))); i++) await new Promise((r) => setTimeout(r, 50));
    assert.ok(await exists(join(dir, "started")), "the pass started");
    const code = await new Promise<number | null>((resolve) => { child.on("close", resolve); child.kill("SIGTERM"); });
    assert.equal(code, 143);
    const receipt = JSON.parse(await readFile(join(cwd, "work/x/receipt.json"), "utf8"));
    assert.equal(receipt.status, "interrupted");
    assert.match(receipt.why, /signal 15/);
    const pid = Number((await readFile(join(dir, "child.pid"), "utf8")).trim());
    await new Promise((r) => setTimeout(r, 300));
    assert.throws(() => process.kill(pid, 0), /ESRCH/);
  });
});
