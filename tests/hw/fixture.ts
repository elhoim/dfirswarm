/**
 * A stopped run for the hardware tests: the release tests' fixture (track
 * P's ledger version 4, custody taken) with the dispositions its defective
 * answers need, in a temporary directory of its own. Prints its paths as
 * JSON; the shell scripts beside this file use them. No key is made here.
 */
import { appendReview } from "../../scripts/review.ts";
import { stoppedRun } from "../release-fixture.ts";

const r = await stoppedRun({ id: process.argv[2] || "shw1" });
const who = { examiner: process.argv[3] || "HW Examiner", examinerId: process.argv[4] || "hw-examiner", key: "hardware" };
await appendReview(r.runs, r.id, r.root, { ...who, action: "adopt", entry_seq: 14 });
await appendReview(r.runs, r.id, r.root, { ...who, action: "inconclusive", entry_seq: 16, note: "the hash is stated nowhere it rests on" });
await appendReview(r.runs, r.id, r.root, { ...who, action: "reject", entry_seq: 17, note: "rests on the superseded answer" });
console.log(JSON.stringify({ runs: r.runs, root: r.root, home: r.home, id: r.id }));
