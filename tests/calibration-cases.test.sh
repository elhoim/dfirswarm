#!/usr/bin/env bash
# The calibration cases, read the way an examiner and the harness read them.
#
# calibration/generate.py proves each planted fact against its own reading
# of the bytes. This suite reads them with the tools a run uses: The Sleuth
# Kit on the drive image (the deleted export recovered whole, the price list
# found in unallocated space and nowhere else, the recipient in notes.txt's
# slack), gzip on every rotated log, sqlite3 on the browser history (the
# phishing visits gone from the tables and still in the file). A tool this
# host lacks is said and its checks skipped. Then each case's goal is
# launched with --no-start, as an operator would, and the prepared run is
# scored with scripts/calibrate.ts: the run's inputs match the truth by
# digest, and the held-back item counts as added only when a second set
# brings it.
set -euo pipefail
unset SWARM_VM_IMAGE SWARM_IMAGES_LOCK DFIRSWARM_HOME
export SWARM_ISOLATION=host
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/calcases.XXXXXX")"
eval "$(sed -n '/^stop_sandbox_daemons()/,/^}/p' "$ROOT/scripts/swarm.sh")"
cleanup() {
  local d
  for d in "$TMP"/runs/*/; do [[ -d "$d" ]] && stop_sandbox_daemons "${d%/}" 2>/dev/null; done
  chmod -R u+w "$TMP" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }
skip() { echo "skip - $*"; }
start() { SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" start "$@" 2>&1; }
sandbox_of() { printf '%s\n' "$1" | sed -n 's/^SANDBOX=//p' | tail -1; }
truth() { jq -er "$2" "$TMP/truth/$1.truth.json"; } # truth <case> <jq path>

command -v python3 >/dev/null || { skip "python3 is not on this host: the cases cannot be generated"; exit 0; }
python3 "$ROOT/calibration/generate.py" --out "$TMP/cases" --truth-dir "$TMP/truth" --seed suite-seed >/dev/null \
  || fail "the generator did not write the cases"
pass "the three cases are generated"

# --- the drive image, through The Sleuth Kit ------------------------------------------------
U="$TMP/cases/usb-departure/inputs"
if command -v fls >/dev/null && command -v icat >/dev/null && command -v blkls >/dev/null; then
  mmls "$U/usb.dd" | grep -q 'DOS FAT16 (0x06)' || fail "mmls finds no FAT16 partition"
  off="$(mmls "$U/usb.dd" | awk '/FAT16/ {print $3 + 0}')"
  [[ "$off" == "2048" ]] || fail "the partition should start at sector 2048, mmls says $off"
  vsn="$(truth usb-departure '.context.drive.vsn | sub("-"; "") | ascii_downcase')"
  fsstat -o "$off" "$U/usb.dd" | grep -qi "Volume ID: 0x$vsn" || fail "fsstat does not show the volume serial the truth names"
  pass "mmls and fsstat read the partition and the volume serial"

  name="$(truth usb-departure .context.files.customers)"
  line="$(fls -o "$off" -r -p "$U/usb.dd" | grep -F "$name")" || fail "fls does not list $name"
  [[ "$line" == *"* "* ]] || fail "fls should list $name as deleted: $line"
  inode="$(printf '%s\n' "$line" | sed -E 's/^[^0-9]*([0-9]+):.*/\1/')"
  want="$(truth usb-departure .context.files.customers_sha256)"
  got="$(icat -r -o "$off" "$U/usb.dd" "$inode" | python3 -c 'import hashlib, sys; print(hashlib.sha256(sys.stdin.buffer.read()).hexdigest())')"
  [[ "$got" == "$want" ]] || fail "icat does not recover the deleted export whole (inode $inode)"
  pass "fls lists the deleted export and icat recovers it byte for byte"

  pl="$(truth usb-departure .context.files.pricelist)"
  fls -o "$off" -r -p "$U/usb.dd" | grep -qF "${pl%.csv}" && fail "no directory entry may name the price list"
  blkls -o "$off" "$U/usb.dd" > "$TMP/unalloc.bin"
  want="$(truth usb-departure .context.files.pricelist_sha256)"
  python3 - "$TMP/unalloc.bin" "$pl" "$want" <<'PY' || fail "the unallocated space does not hold the price list as a gzip stream"
import hashlib, sys, zlib
data = open(sys.argv[1], "rb").read()
i = data.find(b"\x1f\x8b\x08\x08")
assert i >= 0, "no gzip header with a name"
name = data[i + 10:data.index(b"\x00", i + 10)].decode()
assert name == sys.argv[2], name
body = zlib.decompressobj(31).decompress(data[i:])
assert hashlib.sha256(body).hexdigest() == sys.argv[3]
PY
  doc="$(truth usb-departure .context.files.pricelist_doc)"
  python3 -c 'import sys; sys.exit(1 if sys.argv[2].encode() in open(sys.argv[1], "rb").read() else 0)' "$U/usb.dd" "$doc" \
    || fail "the price list's document id must not be readable as plain bytes"
  pass "the price list is only a gzip stream in unallocated space, its name inside the header"

  who="$(truth usb-departure .context.people.recipient.last)"
  ninode="$(fls -o "$off" -p "$U/usb.dd" | grep -F 'notes.txt' | sed -E 's/^[^0-9]*([0-9]+):.*/\1/')"
  icat -o "$off" "$U/usb.dd" "$ninode" | grep -qF "$who" && fail "the recipient must not be in notes.txt's live bytes"
  icat -s -o "$off" "$U/usb.dd" "$ninode" | grep -aqF "$who" || fail "the recipient is not in notes.txt's slack"
  pass "the recipient is in notes.txt's slack and not in its contents"
else
  skip "The Sleuth Kit (mmls, fsstat, fls, icat, blkls) is not on this host: the drive image was held to the generator's own reader only"
fi

# --- the rotated logs and the browser history -----------------------------------------------
n=0
while IFS= read -r -d '' gz; do
  gzip -t "$gz" || fail "$gz is not a valid gzip file"
  n=$((n + 1))
done < <(find "$TMP/cases" -name '*.gz' -print0)
[[ "$n" -ge 10 ]] || fail "expected the rotated logs of two cases, found $n .gz files"
pass "gzip reads all $n rotated logs"

H="$(find "$TMP/cases/invoice-fraud/inputs" -name History)"
if command -v sqlite3 >/dev/null; then
  host="$(truth invoice-fraud .context.phishing.host)"
  cp "$H" "$TMP/History"
  [[ "$(sqlite3 "$TMP/History" 'PRAGMA integrity_check')" == "ok" ]] || fail "the History database is not sound"
  [[ "$(sqlite3 "$TMP/History" "SELECT count(*) FROM urls WHERE url LIKE '%$host%'")" == "0" ]] || fail "the phishing page is still in the live urls table"
  seq="$(sqlite3 "$TMP/History" "SELECT seq FROM sqlite_sequence WHERE name = 'urls'")"
  max="$(sqlite3 "$TMP/History" 'SELECT max(id) FROM urls')"
  [[ "$seq" -gt "$max" ]] || fail "the urls sequence should show rows beyond the live ones ($seq, $max)"
  grep -aqF "$host" "$H" || fail "the phishing page's bytes are not left in the file"
  pass "sqlite3 shows the phishing visits gone from the tables, and the file still holds them"
else
  skip "sqlite3 is not on this host"
fi

# --- the harness takes each goal, and the scorer each prepared run --------------------------
for c in usb-departure web-intrusion invoice-fraud; do
  out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/cases/$c/goal.md" \
    --inputs "$TMP/cases/$c/inputs" --label "cal-$c")"
  sb="$(sandbox_of "$out")"
  [[ -n "$sb" && -f "$sb/SWARM.md" ]] || fail "$c: the kickoff did not prepare a run: $out"
  grep -q '^### Questions the report has to answer' "$sb/SWARM.md" || fail "$c: the contract lost the questions"
  grep -qE '^(more_evidence|summary|title): ' "$sb/SWARM.md" && fail "$c: the metadata block leaked into the contract"
  want="$(jq '.inputs | length' "$TMP/cases/$c/case.json")"
  [[ "$(jq '.files | length' "$sb/inputs.json")" == "$want" ]] || fail "$c: the manifest should list the case's $want files"
  score="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/calibrate.ts" "$sb" --truth "$TMP/truth/$c.truth.json" --json)" \
    || fail "$c: calibrate.ts did not score the prepared run"
  [[ "$(jq '.inputs_match.matched' <<<"$score")" == "$want" ]] || fail "$c: every input should match the truth by digest"
  [[ "$(jq '.late[0].added' <<<"$score")" == "false" ]] || fail "$c: the late item is not in this run"
  [[ "$(jq '.summary.unanswered' <<<"$score")" == "$(jq '[.questions[] | select(.scored)] | length' <<<"$score")" ]] \
    || fail "$c: a run with no answers has every question unanswered"
  [[ -f "$TMP/truth/$c.$(basename "$sb").score.json" ]] || fail "$c: the score's JSON should be beside the truth"
  pass "$c: the goal launches, and the prepared run scores against the truth by digest"
done

# The held-back item added while the run is prepared, the way a case gets it:
# `swarm.sh evidence add`, an inventory revision in the store, found by the
# scorer by its digest on the journal's evidence_added line.
c=invoice-fraud
out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/cases/$c/goal.md" \
  --inputs "$TMP/cases/$c/inputs" --label "cal-add")"
sb="$(sandbox_of "$out")"
id="$(jq -r '.runs[] | select(.label == "cal-add") | .id' "$TMP/runs/registry.json")"
[[ -n "$sb" && -n "$id" ]] || fail "the kickoff for evidence add failed: $out"
late="$(jq -r '.late[0].path' "$TMP/cases/$c/case.json")"
out="$(SWARM_RUNS_DIR="$TMP/runs" bash "$ROOT/scripts/swarm.sh" evidence "$id" add "$TMP/cases/$c/$late" --why "finance supplied the payment run export on request" 2>&1)" || fail "evidence add of the late item failed: $out"
grep -q '^Added ev-0001 (acquired_evidence; 1 file(s)' <<<"$out" || fail "evidence add did not say what it added: $out"
score="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/calibrate.ts" "$sb" --truth "$TMP/truth/$c.truth.json" --json)"
[[ "$(jq '.late[0].added' <<<"$score")" == "true" ]] || fail "the late item added with evidence add should count as added: $(jq -c '.late' <<<"$score")"
jq -e '.late[0].how | test("evidence added as import:ev-0001/")' <<<"$score" >/dev/null || fail "the scorer did not tell the late item by its evidence_added digest: $(jq -c '.late' <<<"$score")"
pass "the late item added with swarm.sh evidence add is found by its digest on the journal's evidence_added line"

# The held-back item as a second set at kickoff: the older way, still read.
c=web-intrusion
out="$(start --model solo/model --n 2 --cap-usd 1 --no-start --goal-file "$TMP/cases/$c/goal.md" \
  --inputs "$TMP/cases/$c/inputs" --inputs "$TMP/cases/$c/late" --label "cal-late")"
sb="$(sandbox_of "$out")"
[[ -n "$sb" ]] || fail "the kickoff with the late item as a second set failed: $out"
score="$(node --experimental-strip-types --no-warnings "$ROOT/scripts/calibrate.ts" "$sb" --truth "$TMP/truth/$c.truth.json" --json)"
[[ "$(jq '.late[0].added' <<<"$score")" == "true" ]] || fail "the late item given as a second set should count as added"
[[ "$(jq -r '.questions[] | select(.id == "4") | .scored_as' <<<"$score")" == "present" ]] || fail "with the late item, question 4 is scored as answerable"
pass "the late item given as a second set is found by its digest, and the question it settles is scored as answerable"
