/**
 * The cloud pack: signin_analyse, against Microsoft Graph's signIn resource (id, createdDateTime, userPrincipalName,
 * userId, appDisplayName, appId, ipAddress, clientAppUsed, correlationId, conditionalAccessStatus,
 * appliedConditionalAccessPolicies, authenticationRequirement, authenticationDetails, status{errorCode, failureReason,
 * additionalDetails}, deviceDetail, location{city, countryOrRegion, geoCoordinates}), the portal's CSV columns, and the
 * Google Reports API activity (id{time, uniqueQualifier, applicationName, customerId}, actor{email}, ipAddress,
 * events[{type, name, parameters[{name, value}]}]). Every fixture is built by the test from those layouts.
 */
import assert from "node:assert/strict";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { test } from "node:test";
import { SIGNIN, asJob, body, everythingBut, exists, filesUnder, put, refused, rowsOf, tool, withDir } from "./cloud-pack-harness.ts";
import type { Json } from "./cloud-pack-harness.ts";

/** A Graph signIn. */
function signIn(i: number, time: string, code: number | null, over: Json = {}): Json {
  return {
    id: `signin-${i}`,
    createdDateTime: time,
    userPrincipalName: "alice@example.org",
    userId: "user-guid-1",
    appDisplayName: "Office 365 Exchange Online",
    appId: "00000002-0000-0ff1-ce00-000000000000",
    ipAddress: "198.51.100.1",
    clientAppUsed: "Browser",
    correlationId: `corr-${i}`,
    conditionalAccessStatus: "success",
    isInteractive: true,
    authenticationRequirement: "multiFactorAuthentication",
    appliedConditionalAccessPolicies: [{ id: "pol-1", displayName: "Require MFA for all users", enforcedGrantControls: ["Mfa"], enforcedSessionControls: [], result: "success" }],
    authenticationDetails: [{ authenticationStepDateTime: time, authenticationMethod: "Password", authenticationMethodDetail: "Password in the cloud", succeeded: code === 0 || code === null, authenticationStepResultDetail: "Correct password", authenticationStepRequirement: "Primary authentication" }],
    status: { errorCode: code, failureReason: code ? "Invalid username or password." : null, additionalDetails: null },
    deviceDetail: { deviceId: "", displayName: "", operatingSystem: "Windows 11", browser: "Edge 120.0.0", isCompliant: false, isManaged: false, trustType: "" },
    location: { city: "Istanbul", state: "Istanbul", countryOrRegion: "TR", geoCoordinates: {} },
    ...over,
  };
}

const graph = (...rows: Json[]): string => JSON.stringify({ "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#auditLogs/signIns", value: rows });

async function run(cwd: string, name: string, text: string, args: Json = {}): Promise<Json> {
  await put(cwd, `work/ev/${name}`, text);
  return body(await tool(SIGNIN, cwd, { path: `work/ev/${name}`, ...args }));
}

const csvLine = (cells: string[]): string => cells.map((c) => (/[",\r\n]/.test(c) ? `"${c.replaceAll('"', '""')}"` : c)).join(",");
const PORTAL = ["Date (UTC)", "Request ID", "Correlation ID", "User", "Username", "Application", "IP address", "Location", "Status", "Sign-in error code", "Failure reason", "Client app", "Authentication requirement", "Conditional Access"];
const portalRow = (i: number, date: string, status: string, code: string, over: Record<string, string> = {}): string[] => {
  const v: Record<string, string> = { "Date (UTC)": date, "Request ID": `req-${i}`, "Correlation ID": `corr-${i}`, User: "Alice", Username: "alice@example.org", Application: "Office 365", "IP address": "198.51.100.1", Location: "Istanbul, TR", Status: status, "Sign-in error code": code, "Failure reason": "", "Client app": "Browser", "Authentication requirement": "Multifactor authentication", "Conditional Access": "Success", ...over };
  return PORTAL.map((k) => v[k]);
};
const portalCsv = (...rows: string[][]): string => [csvLine(PORTAL), ...rows.map(csvLine)].join("\r\n") + "\r\n";

// ---- outcome -----------------------------------------------------------------------------------------------------------------

test("a status that is neither a success nor a failure is an unknown outcome, not a failure", async () => {
  await withDir(async (cwd) => {
    const csv = portalCsv(portalRow(1, "2026-02-14T09:00:00Z", "Success", "0"), portalRow(2, "2026-02-14T09:01:00Z", "Interrupted", ""), portalRow(3, "2026-02-14T09:02:00Z", "Failure", "50126"));
    const out = await run(cwd, "s.csv", csv);
    assert.deepEqual(out.events.map((e: Json) => e.success), [true, null, false], "success is present and null for the unknown one");
    assert.deepEqual([out.successes, out.failures, out.unknown_outcome], [1, 1, 1]);
    const unknown = out.events[1];
    assert.equal(unknown.result_code, "Interrupted");
    assert.match(unknown.outcome_basis, /neither a success nor a failure value/);
  });
});

test("a result code is glossed by the tool and the provider's own words are kept as written, and 50158 is not called a conditional access failure", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, "s.json", graph(signIn(1, "2026-02-14T09:00:00Z", 50158, { status: { errorCode: 50158, failureReason: "External security challenge was not satisfied.", additionalDetails: "details as written" } })));
    const e = out.events[0];
    assert.equal(e.failure_reason, "External security challenge was not satisfied.");
    assert.equal(e.additional_details, "details as written");
    assert.equal(e.result, "external security challenge");
    assert.doesNotMatch(JSON.stringify(out), /conditional access failed/i);
    assert.equal(e.success, false);
  });
});

// ---- formats -------------------------------------------------------------------------------------------------------------------

test("a .jsonl file is read as JSON Lines, and the format is the content's, not the name's", async () => {
  await withDir(async (cwd) => {
    const jsonl = [signIn(1, "2026-02-14T09:00:00Z", 0), signIn(2, "2026-02-14T09:05:00Z", 50126)].map((r) => JSON.stringify(r)).join("\n") + "\n";
    const out = await run(cwd, "export.jsonl", jsonl);
    assert.equal(out.event_count, 2);
    assert.equal(out.coverage.records_rejected, 0);
    assert.equal(out.status, "complete");
    const fromName = await run(cwd, "really-csv.json", portalCsv(portalRow(1, "2026-02-14T09:00:00Z", "Success", "0")));
    assert.equal(fromName.event_count, 1);
    const census = await rowsOf(cwd, fromName, "file_census");
    assert.deepEqual([census[0].format, census[0].format_basis], ["csv", "the content"]);
  });
});

test("a malformed line, a value that is not a record and a truncated file are counted, located and listed; the rest is read", async () => {
  await withDir(async (cwd) => {
    const text = [JSON.stringify(signIn(1, "2026-02-14T09:00:00Z", 0)), "{broken", "42", JSON.stringify(signIn(2, "2026-02-14T09:05:00Z", 0))].join("\n");
    const out = await run(cwd, "x.jsonl", text);
    assert.equal(out.status, "partial");
    assert.equal(out.event_count, 2);
    assert.equal(out.coverage.records_rejected, 2);
    const rejected = await rowsOf(cwd, out, "rejected_records");
    assert.deepEqual(rejected.map((r: Json) => [r.record, r.line]), [[2, 2], [3, 3]]);
    assert.match(out.file_problems.join(" "), /record 2 at line 2/);
  });
});

test("a response that names a next page is partial, and the token is never printed", async () => {
  await withDir(async (cwd) => {
    const g = JSON.stringify({ value: [signIn(1, "2026-02-14T09:00:00Z", 0)], "@odata.nextLink": "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=SKIPTOKENVALUE0123456789abcdef" });
    const out = await run(cwd, "page.json", g);
    assert.equal(out.status, "partial");
    assert.deepEqual(out.pagination_markers.map((m: Json) => m.keys), [["@odata.nextLink"]]);
    assert.ok(!JSON.stringify(out).includes("SKIPTOKENVALUE0123456789abcdef"));
    const google = JSON.stringify({ kind: "admin#reports#activities", items: [], nextPageToken: "GOOGLEPAGETOKEN0123456789abcdef" });
    const g2 = await run(cwd, "g.json", google);
    assert.equal(g2.status, "partial");
    assert.ok(!JSON.stringify(g2).includes("GOOGLEPAGETOKEN0123456789abcdef"));
  });
});

test("a Google activity is expanded to one event per nested event, with the activity id and the event's position kept, and login_failure is a failure", async () => {
  await withDir(async (cwd) => {
    const activity = (qualifier: string, name: string, time: string): Json => ({
      kind: "admin#reports#activity",
      id: { time, uniqueQualifier: qualifier, applicationName: "login", customerId: "C0abcdef1" },
      actor: { email: "carol@example.org", profileId: "1234567890" },
      ipAddress: "203.0.113.50",
      events: [{ type: "login", name: "login_challenge", parameters: [{ name: "login_challenge_method", value: "totp" }] }, { type: "login", name, parameters: [{ name: "login_type", value: "google_password" }] }],
    });
    const items = [activity("q-1", "login_failure", "2026-02-14T09:00:00.000Z"), activity("q-2", "login_success", "2026-02-14T09:01:00.000Z")];
    const out = await run(cwd, "g.json", JSON.stringify({ kind: "admin#reports#activities", items }));
    assert.equal(out.event_count, 4);
    assert.deepEqual(out.events.map((e: Json) => [e.record, e.event_index, e.success]), [[1, 0, null], [1, 1, false], [2, 0, null], [2, 1, true]]);
    assert.deepEqual(out.events[1].activity_id, { time: "2026-02-14T09:00:00.000Z", uniqueQualifier: "q-1", applicationName: "login", customerId: "C0abcdef1" });
    assert.equal(out.events[1].user, "carol@example.org");
    assert.equal(out.events[1].client, "google_password");
    assert.equal(out.events[1].time_utc, "2026-02-14T09:00:00.000Z");
    assert.deepEqual(out.events[0].event_parameters, { login_challenge_method: "totp" });
  });
});

// ---- time ---------------------------------------------------------------------------------------------------------------------

test("a time with no zone is refused unless assume_utc says it is UTC; with it the answer records the assumption", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/z.json", graph(signIn(1, "2026-02-14T09:00:00", 0), signIn(2, "2026-02-14T09:05:00Z", 0)));
    const refusal = refused(await tool(SIGNIN, cwd, { path: "work/ev/z.json", out_file: "work/s1/events.jsonl" }));
    assert.equal(refusal.status, "failed");
    assert.match(refusal.error, /1 record\(s\) carry a time with no zone \(the first is record 1 at line 1: 2026-02-14T09:00:00\)/);
    assert.match(refusal.error, /assume_utc: true/);
    assert.equal(refusal.records_without_a_zone, 1);
    assert.equal(await exists(join(cwd, "work/s1/events.jsonl")), false, "a refusal writes nothing");
    const allowed = body(await tool(SIGNIN, cwd, { path: "work/ev/z.json", assume_utc: true }));
    assert.deepEqual(allowed.events.map((e: Json) => [e.time, e.time_utc, e.time_status]), [["2026-02-14T09:00:00", "2026-02-14T09:00:00Z", "assumed_utc"], ["2026-02-14T09:05:00Z", "2026-02-14T09:05:00Z", "zoned"]]);
    assert.match(allowed.assumptions.join(" "), /times with no zone were read as UTC because assume_utc was set: 1 event/);
  });
});

test("a column named Date (UTC) is read as UTC on its own say-so, and the basis says so; a day/month/year string needs a date order", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, "p.csv", portalCsv(portalRow(1, "2026-02-14 09:00:00", "Success", "0")));
    assert.equal(out.events[0].time_utc, "2026-02-14T09:00:00Z");
    assert.equal(out.events[0].time_basis, "the column is named Date (UTC)");
    assert.match(out.assumptions.join(" "), /column named Date \(UTC\)/);
    const slashed = portalCsv(portalRow(1, "03/04/2026 12:00:00", "Success", "0")).replace("Date (UTC)", "Timestamp");
    await put(cwd, "work/ev/s.csv", slashed);
    const refusal = refused(await tool(SIGNIN, cwd, { path: "work/ev/s.csv", assume_utc: true }));
    assert.match(refusal.error, /both 12 or less.*date_order/);
    const declared = body(await tool(SIGNIN, cwd, { path: "work/ev/s.csv", assume_utc: true, date_order: "dmy" }));
    assert.equal(declared.events[0].time_utc, "2026-04-03T12:00:00Z");
  });
});

// ---- the leads ---------------------------------------------------------------------------------------------------------------

test("three failures thirty days before a success are not a burst; three within minutes are, and the answer says which addresses and codes", async () => {
  await withDir(async (cwd) => {
    const farApart = graph(
      signIn(1, "2026-01-01T09:00:00Z", 50126), signIn(2, "2026-01-01T09:01:00Z", 50126), signIn(3, "2026-01-01T09:02:00Z", 50126),
      signIn(4, "2026-01-31T09:00:00Z", 0),
    );
    const none = await run(cwd, "far.json", farApart, { burst_window_seconds: 86400 });
    assert.deepEqual(none.failure_bursts_before_success, []);
    const dflt = await run(cwd, "far.json", farApart);
    assert.deepEqual(dflt.failure_bursts_before_success, [], "the default window is an hour");

    const close = graph(
      signIn(1, "2026-02-14T09:00:00Z", 50126, { ipAddress: "192.0.2.10" }), signIn(2, "2026-02-14T09:01:00Z", 50076, { ipAddress: "192.0.2.10" }), signIn(3, "2026-02-14T09:02:00Z", 50126, { ipAddress: "192.0.2.10" }),
      signIn(4, "2026-02-14T09:03:00Z", 0, { ipAddress: "203.0.113.5" }),
    );
    const burst = await run(cwd, "close.json", close);
    assert.equal(burst.failure_bursts_before_success.length, 1);
    const b = burst.failure_bursts_before_success[0];
    assert.deepEqual([b.failures_before, b.failure_result_codes, b.failure_addresses, b.success_address_among_failure_addresses], [3, { 50126: 2, 50076: 1 }, { "192.0.2.10": 3 }, false]);
    assert.equal(b.success.event_id, "signin-4");
    assert.deepEqual(b.failure_events.map((f: Json) => f.event_id), ["signin-1", "signin-2", "signin-3"]);
  });
});

test("failures are counted per account and application, and an unknown outcome ends a run", async () => {
  await withDir(async (cwd) => {
    const other = { appDisplayName: "Azure Portal" };
    const rows = graph(
      signIn(1, "2026-02-14T09:00:00Z", 50126), signIn(2, "2026-02-14T09:01:00Z", 50126, other), signIn(3, "2026-02-14T09:02:00Z", 50126), signIn(4, "2026-02-14T09:03:00Z", 50126, other),
      signIn(5, "2026-02-14T09:04:00Z", 0),
    );
    const out = await run(cwd, "apps.json", rows);
    assert.deepEqual(out.failure_bursts_before_success, [], "two failures in each application, then a success in one: no application has three");
    const interrupted = graph(signIn(1, "2026-02-14T09:00:00Z", 50126), signIn(2, "2026-02-14T09:01:00Z", 50126), { ...signIn(3, "2026-02-14T09:02:00Z", null), status: { errorCode: null, failureReason: "Interrupted" } }, signIn(4, "2026-02-14T09:03:00Z", 50126), signIn(5, "2026-02-14T09:04:00Z", 0));
    const after = await run(cwd, "interrupted.json", interrupted);
    assert.deepEqual(after.failure_bursts_before_success, []);
  });
});

test("every field a lead depends on is kept: ids, correlation id, authentication details, applied policies, device context, the raw record and where it came from", async () => {
  await withDir(async (cwd) => {
    const out = await run(cwd, "s.json", graph(signIn(1, "2026-02-14T09:00:00Z", 0, { authenticationRequirement: "singleFactorAuthentication", tokenIssuerType: "AzureAD", uniqueTokenIdentifier: "abcDEF123_uniq" })));
    const e = out.events[0];
    assert.equal(e.event_id, "signin-1");
    assert.equal(e.correlation_id, "corr-1");
    assert.equal(e.user_id, "user-guid-1");
    assert.equal(e.authentication_details[0].authenticationMethod, "Password");
    assert.equal(e.conditional_access_policies[0].displayName, "Require MFA for all users");
    assert.deepEqual([e.token_issuer_type, e.unique_token_identifier], ["AzureAD", "abcDEF123_uniq"]);
    assert.equal(e.device_detail.operatingSystem, "Windows 11");
    assert.equal(e.raw_record.id, "signin-1");
    assert.deepEqual([e.record, e.line, e.event_index ?? null, e.parser], [1, 1, null, "signin_analyse/3"]);
    assert.equal(e.source_file.endsWith("s.json"), true);
    assert.equal(out.single_factor_successes.length, 1);
    assert.equal(out.single_factor_successes[0].event_id, "signin-1");
    assert.equal(out.single_factor_successes[0].correlation_id, "corr-1");
  });
});

test("an address seen once is said to be once in this export, and the heuristic is named for what it is", async () => {
  await withDir(async (cwd) => {
    const rows = [1, 2, 3].map((i) => signIn(i, `2026-02-14T09:0${i}:00Z`, 0, { ipAddress: `198.51.100.${i}` })).concat([signIn(4, "2026-02-14T09:04:00Z", 0, { ipAddress: "198.51.100.1" })]);
    const out = await run(cwd, "seen.json", graph(...rows));
    assert.deepEqual(out.addresses_seen_once.map((r: Json) => r.address), ["198.51.100.2", "198.51.100.3"]);
    assert.match(out.addresses_seen_once[0].why, /once among this account's events in this export.*may not hold/);
    assert.doesNotMatch(JSON.stringify(out), /unfamiliar|this account's history/);
  });
});

test("impossible travel carries the speed and the two events, and a record with no user is counted and kept out of the account analysis", async () => {
  await withDir(async (cwd) => {
    const geo = (lat: number, lon: number, country: string): Json => ({ location: { city: "x", countryOrRegion: country, geoCoordinates: { latitude: lat, longitude: lon } } });
    const rows = [signIn(1, "2026-02-14T09:00:00Z", 0, geo(41.0, 29.0, "TR")), signIn(2, "2026-02-14T09:20:00Z", 0, { ...geo(52.5, 13.4, "DE"), ipAddress: "192.0.2.9" }),
      signIn(3, "2026-02-14T09:10:00Z", 0, { userPrincipalName: null, ...geo(0, 0, "XX") }), signIn(4, "2026-02-14T09:11:00Z", 0, { userPrincipalName: null, ...geo(60, 60, "RU") })];
    const out = await run(cwd, "t.json", graph(...rows));
    assert.equal(out.impossible_travel.length, 1);
    const t = out.impossible_travel[0];
    assert.deepEqual([t.basis, t.coarse, t.from.event_id, t.to.event_id], ["coordinates", false, "signin-1", "signin-2"]);
    assert.ok(t.implied_speed_kmh > 900);
    assert.equal(out.coverage.events_without_user, 2);
    assert.equal(out.accounts, 1);
    const coarse = await run(cwd, "c.json", graph(signIn(1, "2026-02-14T09:00:00Z", 0), signIn(2, "2026-02-14T09:20:00Z", 0, { location: { city: "Berlin", countryOrRegion: "DE", geoCoordinates: {} } })));
    assert.deepEqual([coarse.impossible_travel[0].coarse, coarse.impossible_travel[0].basis], [true, "country change only"]);
  });
});

test("a large export is analysed from a database on disk and every event is kept", async () => {
  await withDir(async (cwd) => {
    const rows = Array.from({ length: 30000 }, (_, i) => signIn(i, new Date(Date.UTC(2026, 1, 14, 0, 0, i % 86000)).toISOString().replace(".000Z", "Z"), i % 7 === 0 ? 50126 : 0, { userPrincipalName: `user${i % 40}@example.org`, ipAddress: `198.51.100.${i % 200}` }));
    const out = await run(cwd, "many.json", graph(...rows), { limit: 20 });
    assert.equal(out.event_count, 30000);
    assert.equal(out.accounts, 40);
    assert.equal(out.coverage.analysis_kept_in, "a temporary file");
    assert.equal((await rowsOf(cwd, out, "events")).length, 30000);
  });
});

// ---- secrets and where output goes --------------------------------------------------------------------------------------------

const JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
const PASSWORD = "Hunter2-correct-horse";
const NEEDLES = [JWT, "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0", PASSWORD, "correct-horse"];

test("a credential-shaped value in a record is withheld from every row, the raw record and every file; the sealed values file holds it only in a job", async () => {
  await withDir(async (cwd) => {
    const row = signIn(1, "2026-02-14T09:00:00Z", 50126, { userAgent: `custom-agent token=${JWT}`, status: { errorCode: 50126, failureReason: `rejected password=${PASSWORD}`, additionalDetails: null }, clientSecret: PASSWORD });
    await put(cwd, `work/ev/${JWT}.json`, graph(row));
    const plain = await asJob(SIGNIN, cwd, { path: `work/ev/${JWT}.json`, limit: 1 }, {}, "out", "jplain");
    const parsed = body(plain);
    const all = await everythingBut(cwd, plain.stdout + plain.stderr, []);
    for (const needle of NEEDLES) assert.ok(!all.includes(needle), `the answer and its files hold ${needle.slice(0, 12)}...`);
    assert.ok(parsed.values_withheld.count >= 3, JSON.stringify(parsed.values_withheld.by_reason));
    assert.equal(parsed.events[0].user, "alice@example.org", "a user name is personal data and stays");
    assert.match(parsed.sensitive_output.personal_data, /user names, addresses/);

    const outside = refused(await tool(SIGNIN, cwd, { path: `work/ev/${JWT}.json`, write_values: true }));
    assert.match(outside.error, /write_values is refused outside a job/);
    const sealed = body(await asJob(SIGNIN, cwd, { path: `work/ev/${JWT}.json`, write_values: true }, {}, "out", "jsealed"));
    const file = join(cwd, "out", "signin-values.jsonl");
    assert.equal((await stat(file)).mode & 0o777, 0o600);
    const values = await readFile(file, "utf8");
    assert.ok(values.includes(PASSWORD) && values.includes(JWT));
    assert.ok(sealed.secret_values.written >= 3);
    const second = refused(await asJob(SIGNIN, cwd, { path: `work/ev/${JWT}.json`, write_values: true }, {}, "out", "jsealed"));
    assert.match(second.error, /the values file already exists/);
    assert.equal(await readFile(file, "utf8"), values);
  });
});

test("an out_file is never replaced by a smaller result, a job writes only under $OUT, and the whole is paged past limit", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/s.json", graph(signIn(1, "2026-02-14T09:00:00Z", 0), signIn(2, "2026-02-14T09:05:00Z", 50126)));
    body(await tool(SIGNIN, cwd, { path: "work/ev/s.json", out_file: "work/s1/events.jsonl" }));
    const kept = await readFile(join(cwd, "work/s1/events.jsonl"), "utf8");
    const second = body(await tool(SIGNIN, cwd, { path: "work/ev/s.json", out_file: "work/s1/events.jsonl", user: "nobody" }));
    assert.equal(await readFile(join(cwd, "work/s1/events.jsonl"), "utf8"), kept);
    assert.equal(second.complete_events, "work/s1/events.2.jsonl");
    const refusedOut = refused(await asJob(SIGNIN, cwd, { path: "work/ev/s.json", out_file: "work/events.jsonl" }));
    assert.match(refusedOut.error, /not under this job's output directory/);
    const paged = body(await asJob(SIGNIN, cwd, { path: "work/ev/s.json", limit: 1 }, {}, "out2"));
    assert.match(paged.pages.events.all_results, /^store\/jobs\/j\d+\/out\/tool-output\/signin_analyse-[0-9a-f]{16}\.jsonl$/);
    assert.equal((await rowsOf(cwd, paged, "events", "out2")).length, 2);
    assert.deepEqual(await filesUnder(join(cwd, "work", "ev")), ["s.json"]);
  });
});

test("a path that is a directory, a missing path and an unsupported file are JSON errors with counts", async () => {
  await withDir(async (cwd) => {
    await put(cwd, "work/ev/x.json", JSON.stringify({ not: "a sign-in export" }));
    const dir = refused(await tool(SIGNIN, cwd, { path: "work/ev" }));
    assert.match(dir.error, /regular file/);
    const missing = refused(await tool(SIGNIN, cwd, { path: "work/ev/none.json" }));
    assert.match(missing.error, /no such file/);
    const bad = refused(await tool(SIGNIN, cwd, { path: "work/ev/x.json" }));
    assert.equal(bad.status, "failed");
    assert.equal(bad.coverage.records_rejected, 1);
    assert.match(bad.file_problems.join(" "), /not a sign-in record: none of a user, a time, an address or a result/);
  });
});

test("a lone surrogate in a user name and a time outside the range of a 64-bit nanosecond count do not stop the run", async () => {
  await withDir(async (cwd) => {
    const text = graph(signIn(1, "2026-02-14T09:00:00Z", 0), signIn(2, "9999-12-31T23:59:59Z", 0)).replaceAll("alice@example.org", "al\\ud800ice@example.org");
    const out = await run(cwd, "s.json", text);
    assert.equal(out.event_count, 2);
    assert.deepEqual(out.events.map((e: Json) => e.time_status), ["zoned", "unparseable"]);
    assert.equal(out.accounts, 1);
    assert.match(JSON.stringify(out.events[0].user), /al.ud800ice@example.org/);
  });
});
