/**
 * A report is held against the ledger before the finish, section by section (B7): each question's answer in the report
 * (the line its section leads with, or its table row) against the first line of the question's standing answer, and a
 * count of dated events against the ledger's standing dated events. The fixtures stand in for two kinds of report the
 * runs wrote: one whose sections lead with the exact strings while the ledger holds sentences, and one whose table cites
 * an entry the ledger never had.
 */
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";
import { answerLineKey, datedEvents, reportAgainstLedger, reportAnswers, reportEventCount, reportQuestionOf } from "../extensions/finish.ts";

const FIX = join(import.meta.dirname, "fixtures", "report-against-ledger");
const MD5 = "5f4dcc3b5aa765d61d8327deb882cf99";

test("each section's first answer line is held to its question's standing answer, not the value found anywhere in the report", () => {
  const report = readFileSync(join(FIX, "sections.md"), "utf8");
  const said = reportAnswers(report);
  assert.equal(said.get("question:1"), "DESKTOP-EXAMPLE1_Fiji Standard Time (E-12)", "the labelled answer line");
  assert.equal(said.get("question:2"), "`192.0.2.7:8080` (E-20)", "the quoted question is passed over");
  assert.equal(said.get("question:3"), "Pending.");
  assert.match(said.get("question:4")!, /^The infection file is the macro document/);
  assert.equal(said.has("question:5"), false);
  const answers = [
    // The ledger held sentences where the report held the strings.
    { section: "question:1", seq: 12, value: "The PC name is DESKTOP-EXAMPLE1 and the time zone is Fiji Standard Time" },
    { section: "question:2", seq: 20, value: "192.0.2.7:8080\nfrom the beacon's configuration" },
    { section: "question:3", seq: 25, value: MD5 },
    // The value is in the report, under its section, but the section leads with a sentence: the old check passed it.
    { section: "question:4", seq: 26, value: `invoice.docm_${MD5}` },
    { section: "question:5", seq: 27, value: "mssetup.exe" },
  ];
  const out = reportAgainstLedger(report, answers, 40, 3);
  assert.equal(out.length, 5, JSON.stringify(out, null, 1));
  assert.match(out[0]!, /^the report's section for question:1 leads with "DESKTOP-EXAMPLE1_Fiji Standard Time \(E-12\)", and its standing answer E-12 is "The PC name is DESKTOP-EXAMPLE1 and the time zone is Fiji Standard Time": the report and the ledger must say the same/);
  assert.match(out[1]!, /^the report's section for question:3 leads with "Pending\.", and its standing answer E-25 is "5f4dcc3b5aa765d61d8327deb882cf99"/);
  assert.match(out[2]!, /^the report's section for question:4 leads with "The infection file is the macro document, and its name and hash follow\.", and its standing answer E-26 is "invoice\.docm_5f4dcc3b5aa765d61d8327deb882cf99"/);
  assert.match(out[3]!, /^the report has no section for question:5, whose standing answer is E-27 \(mssetup\.exe\)/);
  assert.equal(out[4], "the report says its timeline holds 4 dated events, and the ledger has 3 standing dated events (an undated or superseded event is not counted)");
  // The same answers held as the report gives them: nothing to say.
  const agreed = reportAgainstLedger(report, [{ section: "question:1", seq: 12, value: "DESKTOP-EXAMPLE1_Fiji Standard Time" }, { section: "question:2", seq: 20, value: "**192.0.2.7:8080**" }], 40, 4);
  assert.deepEqual(agreed.filter((x) => !/question:[34]/.test(x)), []);
});

test("a table's rows are a report's answers too, and an entry it cites that the ledger lacks is named", () => {
  const report = readFileSync(join(FIX, "table.md"), "utf8");
  assert.deepEqual([...reportAnswers(report)], [["question:1", "DESKTOP-EXAMPLE1_Fiji Standard Time"], ["question:2", "192.0.2.7:8080"]]);
  const out = reportAgainstLedger(report, [{ section: "question:1", seq: 12, value: "DESKTOP-EXAMPLE1_Fiji Standard Time" }, { section: "question:2", seq: 20, value: "192.0.2.7:8080" }], 95);
  assert.deepEqual(out, ["the report cites E-97, which the ledger does not have (its last entry is E-95)"]);
  // A question the report answers that the ledger has no standing answer for.
  assert.match(reportAgainstLedger(report, [{ section: "question:1", seq: 12, value: "DESKTOP-EXAMPLE1_Fiji Standard Time" }], 99)[0]!, /^the report's section for question:2 leads with "192\.0\.2\.7:8080", and the ledger has no standing answer for question:2/);
  assert.deepEqual(reportAgainstLedger("", [{ section: "question:2", seq: 1, value: "" }], 1), [], "an answer with no value yet asks nothing of the report");
});

test("only dated events are counted: an event superseded, or with no time that parses, is not one", () => {
  const entries = [
    { seq: 1, kind: "event", ts: "2024-01-15T12:44:22Z" },
    { seq: 2, kind: "event", ts: "2024-01-15T13:00:00+03:00" },
    { seq: 3, kind: "event", ts: "sometime in January" },
    { seq: 4, kind: "event", ts: "2024-01-15T12:50:00Z" },
    { seq: 5, kind: "event", ts: "2024-01-15T12:51:00Z", supersedes: 4 },
    { seq: 6, kind: "finding", ts: "2024-01-15T12:52:00Z" },
  ] as never[];
  assert.equal(datedEvents(entries, new Map([[4, 5]])), 3);
  assert.equal(reportEventCount("The timeline holds 3 dated events."), 3);
  assert.equal(reportEventCount("A timeline of 12 events, from the logon to the wipe."), 12);
  assert.equal(reportEventCount("**7** events on the timeline"), 7);
  assert.equal(reportEventCount("The security log holds 1204 events."), null, "a count of the evidence's own records is not the timeline's");
  assert.deepEqual(reportAgainstLedger("The timeline holds 3 dated events.", [], 6, 3), []);
});

test("the headings that name a question, and the line keys compared", () => {
  for (const [h, q] of [["1. What is it?", "question:1"], ["Q-4", "question:4"], ["Question 12: the account", "question:12"], ["question:7", "question:7"], ["**3**", "question:3"], ["Timeline", null], ["Summary", null], ["2024 in review", null]] as const) assert.equal(reportQuestionOf(h), q, h);
  assert.equal(answerLineKey("**`invoice.docm_ABC`** (E-4, E-9)."), "invoice.docm_abc");
  assert.notEqual(answerLineKey("A_B"), answerLineKey("AB"), "an underscore in a value is kept");
});
