/**
 * The cloud pack: ual_parse, against the unified audit log's documented shapes: the portal's CSV (RecordId, CreationDate,
 * RecordType, Operation, UserId, AuditData, AssociatedAdminUnits...), the PowerShell export (RunspaceId, RecordType,
 * CreationDate, UserIds, Operations, AuditData...), the Management Activity API's native audit event (CreationTime, Id, Operation,
 * OrganizationId, RecordType, ResultStatus, UserKey, UserType, Version, Workload, UserId, ClientIPAddress, and the
 * Name/Value property lists), and a Graph audit log record. Every fixture is built by the test from those layouts.
 */
import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { UAL, asJob, body, everythingBut, exists, filesUnder, put, refused, rowsOf, tool, withDir } from "./cloud-pack-harness.ts";
import type { Json } from "./cloud-pack-harness.ts";

/** A native audit event as the audit schema writes it. */
const audit = (over: Json = {}): Json => ({
  CreationTime: "2026-02-14T09:00:00",
  Id: "rec-1",
  Operation: "MailItemsAccessed",
  OrganizationId: "11111111-2222-3333-4444-555555555555",
  RecordType: 50,
  ResultStatus: "Succeeded",
  UserKey: "10032001EXAMPLE",
  UserType: 0,
  Version: 1,
  Workload: "Exchange",
  UserId: "alice@example.org",
  ClientIPAddress: "203.0.113.7",
  ClientInfoString: "Client=OWA;Action=ViaProxy",
  OperationCount: 3,
  OperationProperties: [{ Name: "MailAccessType", Value: "Bind" }, { Name: "IsThrottled", Value: "False" }],
  Folders: [{ Path: "\\Inbox", FolderItems: [{ Id: "item-a" }, { Id: "item-b" }] }],
  ...over,
});

const csvCell = (v: string): string => `"${v.replaceAll('"', '""')}"`;
/** A portal-style CSV: the columns the export has, AuditData as quoted JSON text. */
function portalCsv(rows: Array<{ id: string; date: string; type: string; op: string; user: string; data: string }>): string {
  const head = "RecordId,CreationDate,RecordType,Operation,UserId,AuditData,AssociatedAdminUnits,AssociatedAdminUnitNames";
  return [head, ...rows.map((r) => [r.id, r.date, r.type, r.op, r.user, csvCell(r.data), "", ""].join(","))].join("\r\n") + "\r\n";
}

async function run(cwd: string, files: Record<string, string | Buffer>, args: Json = {}): Promise<Json> {
  for (const [name, text] of Object.entries(files)) await put(cwd, `work/ev/${name}`, text);
  return body(await tool(UAL, cwd, { path: "work/ev", ...args }));
}

test("a native audit event keeps its operation, user, id, time and every property, where it used to become a file name and a time", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "native.json": JSON.stringify([audit(), audit({ Id: "rec-2", Operation: "New-InboxRule", UserId: "bob@example.org" })]) }, { assume_utc: true });
    assert.deepEqual(out.records.map((r: Json) => [r.operation, r.user, r.record_id, r.workload, r.record_type]), [["MailItemsAccessed", "alice@example.org", "rec-1", "Exchange", 50], ["New-InboxRule", "bob@example.org", "rec-2", "Exchange", 50]]);
    const first = out.records[0];
    assert.equal(first.payload_status, "native");
    assert.equal(first.address, "203.0.113.7");
    assert.equal(first.time, "2026-02-14T09:00:00");
    assert.equal(first.time_utc, "2026-02-14T09:00:00Z");
    assert.equal(first.time_status, "assumed_utc");
    assert.equal(first.audit_data.Folders[0].FolderItems.length, 2);
    assert.equal(first.items_accessed, 2);
    assert.equal(first.operation_count, 3);
    assert.deepEqual([first.source_file.endsWith("native.json"), first.record, first.parser], [true, 1, "ual_parse/3"]);
    assert.deepEqual(out.assumptions ?? [], [], "ual_parse names its assumptions in time_status, per record");
  });
});

test("a Name/Value property keeps its value (MailAccessType: Bind), and duplicate parameter names stay duplicates, in order", async () => {
  await withDir(async (cwd) => {
    const data = audit({
      ExtendedProperties: [{ Name: "MailAccessType", Value: "Sync" }, { Name: "UserAgent", Value: "Mozilla/5.0" }],
      Parameters: [{ Name: "Identity", Value: "first" }, { Name: "Identity", Value: "second" }, { Name: "ForwardTo", Value: "x@example.net" }],
      ModifiedProperties: [{ Name: "Status", NewValue: "Enabled", OldValue: "Disabled" }],
    });
    const out = await run(cwd, { "e.csv": portalCsv([{ id: "rec-1", date: "2026-02-14T09:00:00.0000000Z", type: "ExchangeItemAggregated", op: "MailItemsAccessed", user: "alice@example.org", data: JSON.stringify(data) }]) });
    const r = out.records[0];
    assert.deepEqual(r.mail_access_type, ["Bind", "Sync"], "every MailAccessType the payload names, in order");
    assert.deepEqual(r.audit_data.ExtendedProperties, [{ Name: "MailAccessType", Value: "Sync" }, { Name: "UserAgent", Value: "Mozilla/5.0" }]);
    assert.deepEqual(r.audit_data.Parameters.map((p: Json) => [p.Name, p.Value]), [["Identity", "first"], ["Identity", "second"], ["ForwardTo", "x@example.net"]]);
    assert.deepEqual(r.audit_data.ModifiedProperties, [{ Name: "Status", NewValue: "Enabled", OldValue: "Disabled" }]);
    assert.equal(r.time_utc, "2026-02-14T09:00:00.0000000Z");
    assert.equal(r.time_status, "zoned");
  });
});

test("a Graph audit log record and a value envelope are read, and an envelope that names a next page is partial", async () => {
  await withDir(async (cwd) => {
    const record = { id: "g-1", createdDateTime: "2026-02-14T09:00:00Z", auditLogRecordType: "exchangeAdmin", operation: "Set-Mailbox", userId: "bob@example.org", auditData: audit({ Id: "g-1", Operation: "Set-Mailbox", UserId: "bob@example.org" }) };
    const out = await run(cwd, { "g.json": JSON.stringify({ "@odata.context": "x", value: [record], "@odata.nextLink": "https://graph.microsoft.com/v1.0/x?$skiptoken=PAGETOKENVALUE0123456789abcdef" }) });
    assert.equal(out.records[0].operation, "Set-Mailbox");
    assert.equal(out.status, "partial");
    assert.deepEqual(out.pagination_markers.map((m: Json) => m.keys), [["@odata.nextLink"]]);
    assert.ok(!JSON.stringify(out).includes("PAGETOKENVALUE0123456789abcdef"));
  });
});

// ---- time ------------------------------------------------------------------------------------------------------------------

const slashRows = (dates: string[]) => dates.map((d, i) => ({ id: `rec-${i + 1}`, date: d, type: "ExchangeAdmin", op: "Set-Mailbox", user: "bob@example.org", data: JSON.stringify({ Operation: "Set-Mailbox", UserId: "bob@example.org", Id: `rec-${i + 1}` }) }));

test("03/04/2026 is ambiguous unless a date order is declared or the file's own unambiguous rows prove one, and the answer says which", async () => {
  await withDir(async (cwd) => {
    const alone = await run(cwd, { "a.csv": portalCsv(slashRows(["03/04/2026 12:00:00"])) }, { assume_utc: true });
    assert.equal(alone.records[0].time_utc, null);
    assert.equal(alone.records[0].time_status, "ambiguous_date_order");
    assert.match(alone.date_convention, /^ambiguous: 1 rows/);
    assert.equal(alone.first_record, null);

    const declared = await run(cwd, {}, { assume_utc: true, date_order: "dmy" });
    assert.equal(declared.records[0].time_utc, "2026-04-03T12:00:00Z");
    assert.equal(declared.date_convention, "declared: dmy");
    const us = await run(cwd, {}, { assume_utc: true, date_order: "mdy" });
    assert.equal(us.records[0].time_utc, "2026-03-04T12:00:00Z");
  });
  await withDir(async (cwd) => {
    // The same file with a row that can only be day/month: the order is proved, used and reported.
    const proved = await run(cwd, { "a.csv": portalCsv(slashRows(["03/04/2026 12:00:00", "13/04/2026 08:30:00"])) }, { assume_utc: true });
    assert.deepEqual(proved.records.map((r: Json) => r.time_utc), ["2026-04-03T12:00:00Z", "2026-04-13T08:30:00Z"]);
    assert.equal(proved.date_conventions[0].date_order, "dmy");
    assert.match(proved.date_conventions[0].basis, /detected from 1 unambiguous rows and none that contradict it/);
    // A file that proves both is not applied.
    const both = await run(cwd, { "a.csv": portalCsv(slashRows(["03/04/2026 12:00:00", "13/04/2026 08:30:00", "04/13/2026 08:30:00"])) }, { assume_utc: true });
    assert.equal(both.records[0].time_status, "ambiguous_date_order");
    assert.match(both.date_conventions[0].basis, /contradictory/);
  });
});

test("a time with no zone is not UTC unless assume_utc says so: it is kept raw and undecoded, and a filter that needs it says how many rows it excluded", async () => {
  await withDir(async (cwd) => {
    const files = { "n.json": JSON.stringify([audit({ Id: "a", CreationTime: "2026-02-14T09:00:00" }), audit({ Id: "b", CreationTime: "2026-02-14T10:00:00Z" }), audit({ Id: "c", CreationTime: "not a time" })]) };
    const plain = await run(cwd, files);
    assert.deepEqual(plain.records.map((r: Json) => [r.record_id, r.time_utc ?? null, r.time_status]), [["a", null, "no_zone"], ["b", "2026-02-14T10:00:00Z", "zoned"], ["c", null, "unparseable"]]);
    assert.deepEqual(plain.coverage.time_statuses, { no_zone: 1, zoned: 1, unparseable: 1 });
    assert.equal(plain.first_record, "2026-02-14T10:00:00Z");
    const bounded = await run(cwd, {}, { since: "2026-02-14T09:30:00Z" });
    assert.deepEqual(bounded.records.map((r: Json) => r.record_id), ["b"]);
    assert.equal(bounded.coverage.excluded_for_unreadable_time, 2, "the two rows whose time could not be read are excluded and counted");
  });
});

// ---- coverage ----------------------------------------------------------------------------------------------------------------

test("failed files, rejected rows and rejected payloads are three counts, each located", async () => {
  await withDir(async (cwd) => {
    const csv = portalCsv([
      { id: "ok", date: "2026-02-14T09:00:00Z", type: "ExchangeAdmin", op: "Set-Mailbox", user: "bob@example.org", data: JSON.stringify(audit({ Id: "ok" })) },
      { id: "bad", date: "2026-02-14T09:01:00Z", type: "ExchangeAdmin", op: "Set-Mailbox", user: "bob@example.org", data: "{not json" },
    ]) + "short,row\r\n";
    const out = await run(cwd, { "a.csv": csv, "other.json": JSON.stringify({ not: "an audit export" }) });
    assert.equal(out.status, "partial");
    assert.equal(out.coverage.rows_rejected, 2, "the short row, and the object that is no audit record");
    const census = await rowsOf(cwd, out, "file_census");
    assert.deepEqual(census.map((c: Json) => [c.file.split("/").pop(), c.status, c.rejected, c.payloads_rejected]), [["a.csv", "partial", 1, 1], ["other.json", "unsupported", 1, 0]]);
    assert.equal(out.coverage.payloads_rejected, 1, "the AuditData that is not JSON");
    assert.equal(out.coverage.files_unsupported, 1, "the file that is no audit export");
    assert.equal(out.unreadable_audit_data, 1);
    const rejected = await rowsOf(cwd, out, "rejected_records");
    assert.ok(rejected.some((r: Json) => r.kind === "payload" && r.record === 2 && r.line === 3 && /not valid JSON/.test(r.reason)));
    assert.ok(rejected.some((r: Json) => r.record === 3 && r.line === 4 && /2 fields and the header 8/.test(r.reason)));
    // The record whose payload was bad is still a record, with its outer columns.
    assert.equal(out.records.find((r: Json) => r.record_id === "bad").payload_status, "invalid_json");
  });
});

test("a payload larger than the csv module's default field limit is read, where the whole run used to stop", async () => {
  await withDir(async (cwd) => {
    const items = Array.from({ length: 6000 }, (_, i) => ({ Id: `item-${i}-${"x".repeat(20)}` }));
    const data = audit({ Folders: [{ Path: "\\Inbox", FolderItems: items }] });
    const text = JSON.stringify(data);
    assert.ok(text.length > 131072);
    const out = await run(cwd, { "big.csv": portalCsv([{ id: "rec-1", date: "2026-02-14T09:00:00Z", type: "ExchangeItemAggregated", op: "MailItemsAccessed", user: "a@example.org", data: text }]) });
    assert.equal(out.status, "complete");
    assert.equal(out.records[0].items_accessed, 6000);
  });
});

test("the summary tables describe the records that matched, and the operation census of every row is separate", async () => {
  await withDir(async (cwd) => {
    const rows = [audit({ Id: "1" }), audit({ Id: "2" }), audit({ Id: "3", Operation: "New-InboxRule" }), audit({ Id: "4", Operation: "Send", RecordType: 2 })];
    const out = await run(cwd, { "n.json": JSON.stringify(rows) }, { operations: ["MailItemsAccessed"] });
    assert.deepEqual(out.by_operation, [{ value: "MailItemsAccessed", count: 2 }]);
    assert.deepEqual(out.operations_all_rows.map((r: Json) => [r.value, r.count]), [["MailItemsAccessed", 2], ["New-InboxRule", 1], ["Send", 1]]);
    assert.match(out.table_scope, /matched the filters/);
    const byType = await run(cwd, {}, { record_type: [2] });
    assert.deepEqual(byType.records.map((r: Json) => r.record_id), ["4"], "the record type is a filter now");
    const byName = await run(cwd, { "csv.csv": portalCsv([{ id: "x", date: "2026-02-14T09:00:00Z", type: "ExchangeAdmin", op: "Set-Mailbox", user: "a@b.c", data: JSON.stringify({ Operation: "Set-Mailbox", Id: "x" }) }]) }, { record_type: ["exchangeadmin"] });
    assert.deepEqual(byName.records.map((r: Json) => r.record_id), ["x"]);
  });
});

test("what the tool flags names the operation and does not say what it means", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "n.json": JSON.stringify([audit(), audit({ Id: "2", Operation: "Add service principal." }), audit({ Id: "3", Operation: "SharingSet" })]) });
    const notes = out.records.map((r: Json) => r.notable).join("\n");
    assert.match(notes, /mailbox item access record/);
    assert.match(notes, /not a statement that content was read/);
    assert.match(notes, /not by itself a consent or a permission/);
    assert.doesNotMatch(notes + out.note, /a mailbox was read|anonymous access was granted|2 minutes|two-minute|one-hour/i);
  });
});

test("files are read in a stable order, and a link and a file with another name are named, not followed", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "b.json": JSON.stringify([audit({ Id: "b" })]), "a.json": JSON.stringify([audit({ Id: "a" })]), "z/in.json": JSON.stringify([audit({ Id: "z" })]), "m/in.json": JSON.stringify([audit({ Id: "m" })]), "readme.txt": "hello" });
    assert.deepEqual(out.records.map((r: Json) => r.record_id), ["a", "b", "m", "z"]);
    assert.equal(out.skipped_by_name_count, 1);
    assert.equal(out.status, "complete", "a file with another name is named and counted, and does not make the read partial");
  });
});

// ---- secrets and where output goes ----------------------------------------------------------------------------------------

const JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const PASSWORD = "Hunter2-correct-horse";
const CLIENT_SECRET = "abc8Q~Zq9Xw7Vb6Nm5Lk4Jh3Gf2Dd1Sa0Pp9Oo8Ii";
const NEEDLES = [JWT, "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0", PASSWORD, "correct-horse", CLIENT_SECRET, "Zq9Xw7Vb6Nm5Lk4Jh3Gf2Dd1Sa0Pp9Oo8Ii"];

const secretFiles = (): Record<string, string> => ({
  [`${JWT}.json`]: JSON.stringify([audit({
    Operation: "Set-Mailbox",
    Parameters: [{ Name: "Identity", Value: "alice" }, { Name: "Password", Value: PASSWORD }, { Name: "Note", Value: `use token=${JWT} to sign in` }],
    ModifiedProperties: [{ Name: "ClientSecret", NewValue: CLIENT_SECRET, OldValue: "" }],
    ExtendedProperties: [{ Name: "UserAgent", Value: "Mozilla/5.0" }],
  })]),
});

test("a parameter or property named or shaped like a credential is withheld from every row, path and file; the sealed values file holds the originals only in a job", async () => {
  await withDir(async (cwd) => {
    for (const [name, text] of Object.entries(secretFiles())) await put(cwd, `work/ev/${name}`, text);
    const plain = await asJob(UAL, cwd, { path: "work/ev", limit: 1 }, {}, "out", "jplain");
    const parsed = body(plain);
    const all = await everythingBut(cwd, plain.stdout + plain.stderr, []);
    for (const needle of NEEDLES) assert.ok(!all.includes(needle), `the answer and its files hold ${needle.slice(0, 12)}...`);
    assert.equal(parsed.values_withheld.count, 3, JSON.stringify(parsed.values_withheld.by_reason));
    assert.equal(parsed.records[0].audit_data.Parameters[0].Value, "alice", "an ordinary parameter stays");
    assert.match(parsed.records[0].audit_data.Parameters[1].Value, /withheld: credential-named field, 21 characters/);
    assert.match(parsed.records[0].source_file, /\[withheld: a JSON Web Token/);

    const outside = refused(await tool(UAL, cwd, { path: "work/ev", write_values: true }));
    assert.match(outside.error, /write_values is refused outside a job/);
    const sealed = body(await asJob(UAL, cwd, { path: "work/ev", write_values: true }, {}, "out", "jsealed"));
    const file = join(cwd, "out", "ual-values.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const values = await readFile(file, "utf8");
    for (const needle of [PASSWORD, CLIENT_SECRET, JWT]) assert.ok(values.includes(needle));
    assert.equal(sealed.secret_values.written, 3);
    const second = refused(await asJob(UAL, cwd, { path: "work/ev", write_values: true }, {}, "out", "jsealed"));
    assert.match(second.error, /the values file already exists/);
    assert.equal(await readFile(file, "utf8"), values);
  });
});

test("an out_file is never replaced by a smaller result, and in a job it must be under $OUT", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/n.json", JSON.stringify([audit({ Id: "1" }), audit({ Id: "2", Operation: "New-InboxRule" })]));
    body(await tool(UAL, cwd, { path: "work/ev/n.json", out_file: "work/s1/ual.jsonl" }));
    const kept = await readFile(join(cwd, "work/s1/ual.jsonl"), "utf8");
    const second = body(await tool(UAL, cwd, { path: "work/ev/n.json", out_file: "work/s1/ual.jsonl", operations: ["New-InboxRule"] }));
    assert.equal(await readFile(join(cwd, "work/s1/ual.jsonl"), "utf8"), kept);
    assert.equal(second.complete_records, "work/s1/ual.2.jsonl");
    const refusedOut = refused(await asJob(UAL, cwd, { path: "work/ev/n.json", out_file: "work/ual.jsonl" }));
    assert.match(refusedOut.error, /not under this job's output directory/);
    assert.equal(await exists(join(cwd, "work", "ual.jsonl")), false);
    const paged = body(await asJob(UAL, cwd, { path: "work/ev/n.json", limit: 1 }, {}, "out2"));
    assert.match(paged.pages.records.all_results, /^store\/jobs\/j\d+\/out\/tool-output\/ual_parse-[0-9a-f]{16}\.jsonl$/);
    assert.equal((await rowsOf(cwd, paged, "records", "out2")).length, 2);
    assert.deepEqual(await filesUnder(join(cwd, "work", "ev")), ["n.json"]);
  });
});

test("a path with a name shaped like a credential is not echoed by an error", async () => {
  await withDir(async (cwd) => {
    const out = refused(await tool(UAL, cwd, { path: `work/ev/${JWT}` }));
    assert.ok(!JSON.stringify(out).includes(JWT));
  });
});

test("a delimiter other than a comma is named, not guessed", async () => {
  await withDir(async (cwd) => {
    const semi = "RecordId;CreationDate;RecordType;Operation;UserId;AuditData\r\nr1;2026-02-14T09:00:00Z;1;Set-Mailbox;a@b.c;{}\r\n";
    await put(cwd, "work/ev/semi.csv", semi);
    const out = refused(await tool(UAL, cwd, { path: "work/ev/semi.csv" }));
    assert.equal(out.status, "failed");
    assert.match(JSON.stringify(out.file_problems), /may use another delimiter/);
    await put(cwd, "work/ev/semi.csv", semi.replace("{}", '"{""Operation"":""Set-Mailbox"",""Id"":""r1""}"'));
    const ok = body(await tool(UAL, cwd, { path: "work/ev/semi.csv", delimiter: ";" }));
    assert.equal(ok.records[0].record_id, "r1");
  });
});

test("a time far outside the range of a 64-bit nanosecond count is an unparseable time, not a failure", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, { "n.json": JSON.stringify([audit({ Id: "far", CreationTime: "9999-12-31T23:59:59Z" })]) });
    assert.equal(out.records[0].time_status, "unparseable");
    assert.equal(out.records[0].time_utc, null);
  });
});
