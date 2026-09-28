#!/usr/bin/env node
/**
 * What enters a run after its kickoff, from outside the evidence it was
 * given (docs/adr/0014): evidence acquired later (`swarm.sh evidence <run>
 * add`) and material the operator supplies (`swarm.sh material <run> add`,
 * and a question's attachment given as a file).
 *
 * Both go the store's import path: the file (or directory) is copied into a
 * staging directory outside the run, each copy held to its source's sha256,
 * then sealed as `store/imports/<id>/` (read-only, every file in a manifest,
 * the bytes kept once in the store's blobs) and written on the store
 * journal. Jobs read it as `import:<id>/<path>`, as they read any import;
 * an agent's own VM keeps the view of the run it booted with, so new
 * evidence is read through jobs (a host run's panes read store/ directly).
 * Nothing is mounted into a VM that is running.
 *
 * Each addition is recorded on the ledger as external material (kind
 * `external`) with its provenance {supplied_by, at, from, sha256,
 * permitted_use}: `acquired_evidence` for evidence, `operator_supplied` or
 * `case_material` for material. What each class may be used for is the case
 * policy's (`material_use`).
 *
 * Evidence is an inventory revision: its journal line counts it
 * (`inventory_rev`), the negative bar's inventory revision moves with it,
 * and it is catalogued when the run's catalogue is on. It answers an
 * acquisition request (`--for R-n`: received, then validated against the
 * sha256 the copy was held to), and it reopens what rested on the evidence
 * as it was: the closed leads under the request's questions (and the
 * request's own lead), the answers recorded before it (stale until recorded
 * again) and the acceptances made before it. Under the case policy's
 * `more_evidence: no` it is refused: the case admits no evidence after its
 * kickoff.
 *
 * While the run's hub runs it is the store journal's one writer, so the act
 * is handed to it on its admin socket; with no hub the act is made here.
 *
 *   material.ts evidence-add <sandbox> PATH --why W [--for R-n] [--question Q-n]...
 *        [--sha256 HEX] [--as ID] [--via cli|console] [--hub-admin SOCKET]
 *   material.ts material-add <sandbox> PATH --why W [--class operator_supplied|case_material]
 *        [--sensitive] [--as ID] [--via cli|console] [--hub-admin SOCKET]
 *   material.ts list <sandbox> [--json]
 *
 * Prints one JSON line.
 */
import { createHash } from "node:crypto";
import { createReadStream, existsSync } from "node:fs";
import { chmod, copyFile, lstat, mkdir, readdir, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import * as L from "../extensions/leads.ts";
import * as P from "../extensions/protocol.ts";
import * as Q from "../extensions/questions.ts";
import * as R from "../extensions/requests.ts";
import { permittedUse, readCasePolicy, type SourceClass } from "./case-policy.ts";
import { Journal, sealTree, storePaths } from "./evidence-store.ts";

export type MaterialMode = "evidence" | "material";

export type MaterialRequest = {
  mode: MaterialMode;
  /** The host path: a file or a directory, outside the run. */
  path: string;
  why: string;
  /** Evidence: the acquisition request it answers (R-<n>). */
  for?: string;
  /** Evidence: the questions it bears on, beside the request's. */
  questions?: string[];
  /** Evidence: an acquisition hash of the one file given, held against the copy. */
  sha256?: string;
  /** Material: its class (operator_supplied by default, or case_material). */
  cls?: "operator_supplied" | "case_material";
  /** Material: what it says is sensitive (names, labels and questions may not carry it). */
  sensitive?: boolean;
  /** Who supplied it, in words (an enrolled person as a claim, or the OS account on this host). */
  supplied_by: string;
  via: string;
};

export type MaterialResult = Record<string, unknown> & { ok: boolean };

const sha256Of = (b: string | Buffer) => createHash("sha256").update(b).digest("hex");

async function fileSha(path: string): Promise<string> {
  const h = createHash("sha256");
  await new Promise<void>((ok, fail) => {
    createReadStream(path).on("data", (c) => h.update(c)).on("end", () => ok()).on("error", fail);
  });
  return h.digest("hex");
}

function within(child: string, parent: string): boolean {
  const r = relative(parent, child);
  return r === "" || (!r.startsWith("..") && !r.startsWith(sep));
}

/** The next free import id with this prefix (ev-0001, mat-0001). */
async function nextImportId(S: string, prefix: "ev" | "mat"): Promise<string> {
  const names = await readdir(storePaths(S).imports).catch(() => [] as string[]);
  const n = Math.max(0, ...names.map((x) => Number(new RegExp(`^${prefix}-(\\d{4,})$`).exec(x)?.[1] ?? 0))) + 1;
  return `${prefix}-${String(n).padStart(4, "0")}`;
}

type Walked = { rel: string; abs: string; bytes: number };

/**
 * Every regular file under a path, by lstat: a link inside (never followed)
 * or anything but a file or a directory is named and refused. A link given
 * as the path itself is the operator's, and is followed once, as --inputs
 * follows one.
 */
async function walkSource(root: string): Promise<{ ok: true; top: "file" | "dir"; files: Walked[] } | { ok: false; reason: string }> {
  let real: string;
  try {
    real = await realpath(root);
  } catch {
    return { ok: false, reason: `${root} does not exist` };
  }
  const st = await stat(real);
  if (st.isFile()) return { ok: true, top: "file", files: [{ rel: basename(root), abs: real, bytes: st.size }] };
  if (!st.isDirectory()) return { ok: false, reason: `${root} is neither a file nor a directory` };
  const files: Walked[] = [];
  const refused: string[] = [];
  const visit = async (dir: string, rel: string): Promise<void> => {
    for (const d of await readdir(dir, { withFileTypes: true })) {
      const abs = join(dir, d.name);
      const r = rel ? `${rel}/${d.name}` : d.name;
      if (d.isSymbolicLink()) refused.push(`${r} (a link)`);
      else if (d.isDirectory()) await visit(abs, r);
      else if (d.isFile()) files.push({ rel: r, abs, bytes: (await lstat(abs)).size });
      else refused.push(`${r} (not a regular file)`);
    }
  };
  await visit(real, "");
  if (refused.length) return { ok: false, reason: `${root} holds what is not a regular file: ${refused.join(", ")}; give the files themselves` };
  if (!files.length) return { ok: false, reason: `${root} holds no file` };
  return { ok: true, top: "dir", files };
}

/** The material a run holds: each import with its record, oldest first. */
export async function listMaterial(S: string): Promise<Array<Record<string, unknown>>> {
  const out: Array<Record<string, unknown>> = [];
  const dir = storePaths(S).imports;
  for (const id of (await readdir(dir).catch(() => [] as string[])).sort()) {
    if (!/^(ev|mat)-\d{4,}$/.test(id)) continue;
    try {
      out.push(JSON.parse(await readFile(join(dir, id, "material.json"), "utf8")) as Record<string, unknown>);
    } catch {
      out.push({ import: id, unreadable: true });
    }
  }
  return out;
}

/** The questions of a request and of the addition, as the register names them. */
function questionsOf(req: MaterialRequest, request: R.OperatorRequest | null): string[] {
  return [...new Set([...(request?.questions ?? []), ...(req.questions ?? [])].map((q) => R.questionId(q)).filter(Boolean))];
}

/**
 * The addition, where the store journal is written (the hub, or here when no
 * hub runs): checked, copied and held to its source, sealed, journalled,
 * recorded on the ledger as external material, the acquisition answered,
 * what rested on the evidence as it was reopened, catalogued, and said on
 * the board. Refused before anything is written when it cannot be made
 * whole.
 */
export async function admitMaterial(sandbox: string, req: MaterialRequest, o: { journal?: Journal; catalogue?: (target: string, note: string) => Promise<{ ok: boolean; job?: string; reason?: string }>; catalogueOn?: boolean } = {}): Promise<MaterialResult> {
  const S = resolve(sandbox);
  if (req.mode !== "evidence" && req.mode !== "material") return { ok: false, reason: "an addition is evidence or material" };
  const why = String(req.why ?? "").trim();
  if (!why) return { ok: false, reason: `${req.mode === "evidence" ? "evidence add" : "material add"} says why (--why): what it is and what it is for` };
  if (why.length > 4000) return { ok: false, reason: "--why is at most 4000 characters: nothing is cut, so a longer one is refused" };
  const policy = readCasePolicy(S);
  const cls: SourceClass = req.mode === "evidence" ? "acquired_evidence" : (req.cls ?? "operator_supplied");
  if (req.mode === "material" && !["operator_supplied", "case_material"].includes(cls)) return { ok: false, reason: "--class is operator_supplied or case_material" };
  if (req.mode === "evidence" && policy.more_evidence === "no") {
    return { ok: false, reason: `this case admits no evidence after its kickoff (case policy ${policy.policy}, more_evidence: no): nothing was added. An agent's acquisition is answered "${R.NO_MORE_EVIDENCE}"; a case that must take this evidence is a new run, or material supplied for reference (swarm.sh material <run> add)` };
  }
  const src = resolve(String(req.path ?? ""));
  if (!req.path) return { ok: false, reason: "name the file or directory to add" };
  if (within(src, S) || within(await realpath(src).catch(() => src), await realpath(S).catch(() => S))) return { ok: false, reason: `${req.path} is inside the run: what is in the run is cited as it is (input:, job:, import:), never added again` };
  // The acquisition it answers.
  let request: R.OperatorRequest | null = null;
  if (req.for) {
    if (req.mode !== "evidence") return { ok: false, reason: "--for names the acquisition request evidence answers; material answers none" };
    const m = /^R-?([1-9]\d{0,6})$/i.exec(req.for.trim());
    if (!m) return { ok: false, reason: `--for names a request, R-<n> (got ${JSON.stringify(req.for)})` };
    await R.reconcileRequests(S).catch(() => undefined);
    request = (await R.requestsSnapshot(S)).requests.get(`R-${Number(m[1])}`) ?? null;
    if (!request) return { ok: false, reason: `R-${Number(m[1])} is not a request of this run (swarm.sh requests <run> list)` };
    if (request.kind !== "acquisition") return { ok: false, reason: `${request.rid} is a ${request.kind} request, not an acquisition: evidence answers an acquisition` };
    if (request.stage === "declined" || request.stage === "unavailable" || request.stage === "validated") return { ok: false, reason: `${request.rid} is ${request.stage}${request.closed ? ` (${request.closed.text})` : ""}: add the evidence without --for, naming the questions it bears on (--question Q-n)` };
  }
  const expected = req.sha256 ? String(req.sha256).trim().toLowerCase() : "";
  if (expected && !/^[0-9a-f]{64}$/.test(expected)) return { ok: false, reason: "--sha256 is the file's sha256, 64 hex characters" };
  const walked = await walkSource(src);
  if (!walked.ok) return walked;
  if (expected && walked.files.length !== 1) return { ok: false, reason: "--sha256 holds one file to its acquisition hash; a directory's files are each held to their own sha256 as they are copied" };
  const P_ = storePaths(S);
  const id = await nextImportId(S, req.mode === "evidence" ? "ev" : "mat");
  const staging = join(P_.staging, id);
  await rm(staging, { recursive: true, force: true });
  await mkdir(staging, { recursive: true });
  // Each file copied, then held to the sha256 its source had before the copy: a source that changed while it was copied is refused.
  const files: Array<{ path: string; sha256: string; bytes: number }> = [];
  try {
    for (const f of walked.files) {
      const before = await fileSha(f.abs);
      const dest = join(staging, f.rel);
      await mkdir(dirname(dest), { recursive: true });
      await copyFile(f.abs, dest);
      const copied = await fileSha(dest);
      if (copied !== before) return { ok: false, reason: `${f.rel} changed while it was copied (sha256 ${before} before, ${copied} as copied): add it again once it is still; nothing was added` };
      if (expected && copied !== expected) return { ok: false, reason: `${f.rel}'s sha256 is ${copied}, not the acquisition hash given (${expected}): nothing was added` };
      files.push({ path: f.rel, sha256: copied, bytes: f.bytes });
    }
  } catch (err) {
    await rm(staging, { recursive: true, force: true }).catch(() => undefined);
    return { ok: false, reason: `the copy failed (${(err as Error).message}): nothing was added` };
  }
  const journal = o.journal ?? (await Journal.open(S));
  const sealed = await sealTree(S, staging, join(P_.imports, id, "out"), id, 1, join(P_.imports, id, "manifest.json"));
  // The sealed copy, held again to what was copied: "validated" means these hashes.
  const byPath = new Map(sealed.manifest.files.map((f) => [f.path, f.sha256]));
  const differ = files.filter((f) => byPath.get(f.path) !== f.sha256).map((f) => f.path);
  if (differ.length) return { ok: false, reason: `the sealed copy of ${differ.join(", ")} does not hash as it was copied: store/imports/${id} is kept for the record and cited by nothing` };
  const at = new Date().toISOString();
  const inventoryRev = req.mode === "evidence" ? journal.of("evidence_added").length + 1 : null;
  const questions = req.mode === "evidence" ? questionsOf(req, request) : [];
  // The hub says whether its catalogue is on; with no hub, a run with a job service catalogues it at the hub's next round (a resume).
  const catalogueOn = req.mode === "evidence" && (o.catalogueOn ?? existsSync(join(S, "store", "jobs")));
  const record = {
    v: 1,
    import: id,
    mode: req.mode,
    class: cls,
    at,
    supplied_by: req.supplied_by,
    via: req.via,
    from: src,
    why,
    files,
    manifest_sha256: sealed.manifestSha256,
    permitted_use: permittedUse(policy, cls),
    ...(request ? { request: request.rid } : {}),
    ...(questions.length ? { questions } : {}),
    ...(inventoryRev !== null ? { inventory_rev: inventoryRev } : {}),
    ...(req.sensitive ? { sensitive: true } : {}),
  };
  const recordText = `${JSON.stringify(record, null, 2)}\n`;
  await writeFile(join(P_.imports, id, "material.json"), recordText, { mode: 0o444 });
  await chmod(join(P_.imports, id, "material.json"), 0o444).catch(() => undefined);
  const line = await journal.append({
    type: req.mode === "evidence" ? "evidence_added" : "material_added",
    import: id,
    class: cls,
    files,
    manifest_sha256: sealed.manifestSha256,
    material_json_sha256: sha256Of(recordText),
    by: req.supplied_by,
    why,
    ...(request ? { request: request.rid } : {}),
    ...(questions.length ? { questions } : {}),
    ...(inventoryRev !== null ? { inventory_rev: inventoryRev, catalogue: !catalogueOn ? "off" : o.catalogue ? "queued" : "at the hub's next round" } : {}),
  });
  // On the ledger: external material, with its provenance in the chained core.
  const refs = files.length <= P.LEDGER_MAX_REFS - 1 ? files.map((f) => `import:${id}/${f.path}`) : [`import:${id}`];
  const external = await P.recordExternal(S, {
    value:
      req.mode === "evidence"
        ? `Evidence added after the kickoff (inventory revision ${inventoryRev}): ${files.length} file(s) as import:${id}${request ? `, for ${request.rid}` : ""}: ${why}`
        : `Material supplied (${cls}): ${files.length} file(s) as import:${id}: ${why}`,
    source: `swarm.sh ${req.mode} add, by ${req.supplied_by} (${req.via})`,
    evidence: `store/imports/${id}/material.json and manifest.json; store journal line ${line.seq}`,
    refs,
    source_class: cls,
    provenance: {
      supplied_by: req.supplied_by,
      at,
      from: src,
      sha256: files.length === 1 ? files[0].sha256 : sealed.manifestSha256,
      permitted_use: permittedUse(policy, cls),
      import: id,
      files: files.map((f) => ({ path: f.path, sha256: f.sha256, bytes: f.bytes })),
      ...(files.length > 1 ? { sha256_of: "the import's manifest" } : {}),
      ...(request ? { request: request.rid } : {}),
      ...(inventoryRev !== null ? { inventory_rev: inventoryRev } : {}),
    },
    ...(req.sensitive ? { sensitive: true } : {}),
  });
  const out: MaterialResult = { ok: true, import: id, mode: req.mode, class: cls, files, manifest_sha256: sealed.manifestSha256, journal_seq: line.seq, ...(inventoryRev !== null ? { inventory_rev: inventoryRev } : {}), entry: external.ok ? external.entry.seq : null, ...(external.ok ? {} : { entry_pending: external.reason }), permitted_use: permittedUse(policy, cls) };
  if (req.mode === "material") {
    await P.systemPost(S, { tag: "ask", body: `MATERIAL SUPPLIED as import:${id} (${cls}; use: ${permittedUse(policy, cls)}), ${files.length} file(s): ${files.map((f) => `${f.path} (sha256 ${f.sha256})`).join(", ")}, by ${req.supplied_by}: ${why}. It is supplied material and proves nothing by itself: cite it as import:${id}/<file> and say what it establishes, with its limits; it is on the ledger as E-${external.ok ? external.entry.seq : "?"} (kind external).` }).catch(() => undefined);
    return out;
  }
  // The acquisition answered: received, then validated against the hashes the copy was held to.
  if (request) {
    if (request.stage === "requested") await R.requestAct(S, request.rid, { ev: "stage", by: req.supplied_by, stage: "authorised", why: "the operator supplied the evidence" });
    const recv = await R.requestAct(S, request.rid, { ev: "stage", by: req.supplied_by, stage: "received", why, import: id, ...(inventoryRev !== null ? { inventory_rev: inventoryRev } : {}), sha256: files.map((f) => f.sha256) });
    const val = await R.requestAct(S, request.rid, { ev: "stage", by: "harness", stage: "validated", why: `every file held to the sha256 it had before it was copied${expected ? ", and to the acquisition hash given" : ""}`, import: id, sha256: files.map((f) => f.sha256) });
    out.request = { id: request.rid, received: recv.ok, validated: val.ok, ...(recv.ok ? {} : { reason: recv.reason }), ...(val.ok || !recv.ok ? {} : { reason: val.reason }) };
  }
  // What rested on the evidence as it was, reopened: the closed leads under its questions, and the request's own lead.
  const snap = await L.leadsSnapshot(S);
  const reopened: string[] = [];
  const asQ = (a: string) => R.questionId(a);
  for (const l of snap.state.leads.values()) {
    if (!l.closed || l.closed.disposition === "duplicate" || l.closed.disposition === "withdrawn") continue;
    const serves = l.answers.some((a) => questions.includes(asQ(a)));
    if (!serves && l.id !== request?.lead) continue;
    const r = await L.reopenLead(S, l.id, "harness", `new evidence: import:${id}${request ? ` for ${request.rid}` : ""} (inventory revision ${inventoryRev}): ${why}`, "evidence_added");
    if (r.ok) reopened.push(l.id);
  }
  const arrival = questions.length ? await Q.recordEvidenceArrival(S, questions, { import: `import:${id}`, request: request?.rid ?? null, inventory_rev: inventoryRev, why }) : { recorded: [], unknown: [] };
  out.reopened = { leads: reopened, questions: arrival.recorded, ...(arrival.unknown.length ? { unknown_questions: arrival.unknown } : {}) };
  // Catalogued when the run's catalogue is on: a detect pass over each file, as the system's own.
  if (catalogueOn && o.catalogue) {
    const jobs: string[] = [];
    const refused: string[] = [];
    for (const f of files) {
      const c: { ok: boolean; job?: string; reason?: string } = await o.catalogue(`import:${id}/${f.path}`, `evidence added: import:${id}${request ? ` for ${request.rid}` : ""}`).catch((err: Error) => ({ ok: false, reason: err.message }));
      if (c.ok && c.job) jobs.push(c.job);
      else refused.push(`${f.path}: ${c.reason ?? "refused"}`);
    }
    await journal.append({ type: "evidence_catalogue_queued", import: id, jobs, ...(refused.length ? { refused } : {}) });
    out.catalogue = { jobs, ...(refused.length ? { refused } : {}) };
  } else out.catalogue = catalogueOn ? "at the hub's next round, when the run's catalogue is on" : "off in this run (no job service)";
  await P.systemPost(S, {
    tag: "ask",
    body: [
      `EVIDENCE ADDED (inventory revision ${inventoryRev}) as import:${id}${request ? `, for ${request.rid}` : ""}${questions.length ? `, on ${questions.join(", ")}` : ""}, by ${req.supplied_by}: ${why}.`,
      `Files: ${files.map((f) => `${f.path} (${f.bytes} bytes, sha256 ${f.sha256})`).join("; ")}.`,
      "Read it through a job: job_run with inputs [\"import:" + id + "/<file>\"]; a seat's own VM keeps the view of the run it booted with, and a run with no job service reads store/imports/" + id + "/out/ directly.",
      reopened.length ? `Reopened: ${reopened.join(", ")}.` : "",
      arrival.recorded.length ? `Answers to ${arrival.recorded.join(", ")} recorded before it are stale until recorded again, and an acceptance made before it no longer stands.` : "",
      `It is on the ledger as E-${external.ok ? external.entry.seq : "?"} (kind external, class acquired_evidence).`,
    ].filter(Boolean).join(" "),
  }).catch(() => undefined);
  await R.renderViews(S).catch(() => undefined);
  return out;
}

async function main(argv: string[]): Promise<void> {
  const [cmd, sandboxArg, ...rest] = argv;
  if (!cmd || !sandboxArg) {
    process.stderr.write("usage: material.ts evidence-add|material-add|list <sandbox> ...\n");
    process.exit(2);
  }
  const S = resolve(sandboxArg);
  const emit = (r: Record<string, unknown>) => {
    process.stdout.write(`${JSON.stringify(r)}\n`);
    process.exit(r.ok === false ? 1 : 0);
  };
  if (cmd === "list") {
    const list = await listMaterial(S);
    emit({ ok: true, material: list });
  }
  const valued = new Set(["--why", "--for", "--question", "--sha256", "--class", "--as", "--via", "--hub-admin"]);
  const pos: string[] = [];
  const opts = new Map<string, string[]>();
  const flags = new Set<string>();
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (valued.has(a)) {
      opts.set(a, [...(opts.get(a) ?? []), rest[i + 1] ?? ""]);
      i += 1;
    } else if (a.startsWith("--")) flags.add(a);
    else pos.push(a);
  }
  const one = (k: string) => opts.get(k)?.at(-1);
  if (cmd !== "evidence-add" && cmd !== "material-add") {
    process.stderr.write("usage: material.ts evidence-add|material-add|list <sandbox> ...\n");
    process.exit(2);
  }
  if (!pos[0]) emit({ ok: false, reason: `${cmd === "evidence-add" ? "evidence add" : "material add"} needs the path of the file or directory` });
  // Who supplies it: an enrolled person (a claim), or this host's OS account.
  const QC = await import("./questions-cli.ts");
  const via = one("--via") === "console" ? "console" : "cli";
  const who = QC.actorFor({ ...(one("--as") ? { as: one("--as") } : {}), via });
  if ("why" in who) emit({ ok: false, reason: who.why });
  const actor = (who as { actor: Q.Actor }).actor;
  const req: MaterialRequest = {
    mode: cmd === "evidence-add" ? "evidence" : "material",
    path: resolve(pos[0]),
    why: one("--why") ?? "",
    ...(one("--for") ? { for: one("--for") } : {}),
    ...(opts.get("--question")?.length ? { questions: opts.get("--question") } : {}),
    ...(one("--sha256") ? { sha256: one("--sha256") } : {}),
    ...(one("--class") ? { cls: one("--class") as MaterialRequest["cls"] } : {}),
    ...(flags.has("--sensitive") ? { sensitive: true } : {}),
    supplied_by: Q.originWords(Q.originOf(actor)),
    via,
  };
  const r = await QC.admit(S, one("--hub-admin"), { op: "material", request: req }, () => admitMaterial(S, req));
  emit(r);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => {
    process.stdout.write(`${JSON.stringify({ ok: false, reason: err instanceof Error ? err.message : String(err) })}\n`);
    process.exit(1);
  });
}
