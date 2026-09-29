/**
 * The reverse sweeps of evidence added late, as a step of their own
 * (extensions/store-sweep.ts runReverseSweeps): started detached by an
 * evidence add made with no hub running, which answers the operator as soon
 * as the addition is committed and exits. Rounds until nothing is left, the
 * run ends, or a round records nothing; one such step at a time.
 *
 *   node --experimental-strip-types scripts/reverse-sweep.ts <run>
 */
import { resolve } from "node:path";
import { runReverseSweeps } from "../extensions/store-sweep.ts";

const run = process.argv[2];
if (!run) {
  process.stderr.write("usage: reverse-sweep.ts <run>\n");
  process.exit(2);
}
await runReverseSweeps(resolve(run));
process.exit(0);
