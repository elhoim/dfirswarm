#!/usr/bin/env bash
# Sector 0 must remain 0 after mmls's zero-padded start column is stripped.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

# The catalog script exits if argv is missing, so extract the helper and
# run it — that is the transform kickoff actually uses on each mmls line.
eval "$(sed -n '/^mmls_start_sector()/,/^}/p' "$ROOT/scripts/evidence-catalog.sh")"
[[ "$(type -t mmls_start_sector)" == function ]] || fail "mmls_start_sector missing from evidence-catalog.sh"

[[ "$(mmls_start_sector $'00:  000  0000000000  0001028095   001028096   Linux')" == 0 ]] \
  || fail "sector 0 became empty and would be skipped"
[[ "$(mmls_start_sector $'01:  000  0000002048  0001028095   001026048   NTFS')" == 2048 ]] \
  || fail "a non-zero start sector should keep its value"
pass "mmls start sector 0 is 0, not skipped"

eval "$(sed -n '/^catalog_slug()/,/^}/p' "$ROOT/scripts/evidence-catalog.sh")"
[[ "$(type -t catalog_slug)" == function ]] || fail "catalog_slug missing from evidence-catalog.sh"
[[ "$(catalog_slug "node1/sda.E01")" == "node1_sda.E01" ]] \
  || fail "a nested input should keep its directory in the slug"
[[ "$(catalog_slug "node2/sda.E01")" == "node2_sda.E01" ]] \
  || fail "two inputs with the same basename must not share a slug"
[[ "$(catalog_slug "sda.E01")" == "sda.E01" ]] \
  || fail "a top-level input should keep its basename"
[[ "$(catalog_slug "node1/sda.E01")" != "$(catalog_slug "node2/sda.E01")" ]] \
  || fail "node1/sda.E01 and node2/sda.E01 collided"
pass "catalog slug is the path under inputs/, not the basename"

# Two same-basename images must land in different catalog trees.
TMP="$(mktemp -d "${TMPDIR:-/tmp}/catalog-slug.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/sandbox/inputs/node1" "$TMP/sandbox/inputs/node2"
# mmls is enough for the script to claim a disk image and write partitions.txt
# under $slug/; fsstat/fls may be missing and that only leaves notes.
cat > "$TMP/bin/mmls" <<'EOF'
#!/usr/bin/env bash
cat <<'TABLE'
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
002:  000:000   0000002048   0001028095   001026048    NTFS (0x07)
TABLE
EOF
chmod +x "$TMP/bin/mmls"
dd if=/dev/zero of="$TMP/sandbox/inputs/node1/sda.E01" bs=1024 count=64 status=none
dd if=/dev/zero of="$TMP/sandbox/inputs/node2/sda.E01" bs=1024 count=64 status=none
PATH="$TMP/bin:$PATH" bash "$ROOT/scripts/evidence-catalog.sh" "$TMP/sandbox" >/dev/null
[[ -f "$TMP/sandbox/catalog/node1_sda.E01/partitions.txt" ]] \
  || fail "node1/sda.E01 should catalog under catalog/node1_sda.E01/"
[[ -f "$TMP/sandbox/catalog/node2_sda.E01/partitions.txt" ]] \
  || fail "node2/sda.E01 should catalog under catalog/node2_sda.E01/"
[[ ! -d "$TMP/sandbox/catalog/sda.E01" ]] \
  || fail "a basename-only slug would have overwritten catalog/sda.E01/"
grep -q 'node1/sda.E01' "$TMP/sandbox/catalog/README.md" \
  || fail "the index should name the first nested input"
grep -q 'node2/sda.E01' "$TMP/sandbox/catalog/README.md" \
  || fail "the index should name the second nested input"
pass "two inputs named sda.E01 keep separate catalog trees"

eval "$(sed -n '/^have()/,/^}/p' "$ROOT/scripts/evidence-catalog.sh")"
eval "$(sed -n '/^is_memory_image()/,/^}/p' "$ROOT/scripts/evidence-catalog.sh")"
[[ "$(type -t is_memory_image)" == function ]] || fail "is_memory_image missing from evidence-catalog.sh"
touch "$TMP/sample.pdf" "$TMP/sample.pcap" "$TMP/sample.evtx" "$TMP/sample.mem" "$TMP/sample.dmp" "$TMP/sample.e01"
is_memory_image "$TMP/sample.pdf" && fail "a PDF is not a memory image"
is_memory_image "$TMP/sample.pcap" && fail "a pcap is not a memory image"
is_memory_image "$TMP/sample.evtx" && fail "an EVTX is not a memory image"
is_memory_image "$TMP/sample.e01" && fail "a leftover E01 is a disk image, not memory"
is_memory_image "$TMP/sample.mem" || fail ".mem should be offered to Volatility"
is_memory_image "$TMP/sample.dmp" || fail ".dmp should be offered to Volatility"
pass "memory catalog is gated on the filename, not every leftover ≥64 KB"

# A PDF leftover must not invoke vol; a .mem leftover must, and a missing vol
# is noted only for the memory file.
mkdir -p "$TMP/mem/bin" "$TMP/mem/sandbox/inputs"
dd if=/dev/zero of="$TMP/mem/sandbox/inputs/report.pdf" bs=1024 count=64 status=none
dd if=/dev/zero of="$TMP/mem/sandbox/inputs/dump.mem" bs=1024 count=64 status=none
cat > "$TMP/mem/bin/mmls" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
cp "$TMP/mem/bin/mmls" "$TMP/mem/bin/fsstat"
cat > "$TMP/mem/bin/vol" <<'EOF'
#!/usr/bin/env bash
printf 'vol %s\n' "$*" >> "${VOL_LOG:?}"
echo "not a windows dump"
exit 1
EOF
chmod +x "$TMP/mem/bin/vol" "$TMP/mem/bin/mmls" "$TMP/mem/bin/fsstat"
VOL_LOG="$TMP/mem/vol.log"
# Hide host mmls/fsstat/vol so leftovers reach the memory gate.
hide="$TMP/mem/bin"
PATH="$hide:/usr/bin:/bin" VOL_LOG="$VOL_LOG" \
  bash "$ROOT/scripts/evidence-catalog.sh" "$TMP/mem/sandbox" >/dev/null
[[ -f "$VOL_LOG" ]] || : > "$VOL_LOG"
grep -q 'report.pdf' "$VOL_LOG" && fail "vol ran on a PDF leftover: $(cat "$VOL_LOG")"
grep -q 'dump.mem' "$VOL_LOG" || fail "vol should probe a .mem leftover: $(cat "$VOL_LOG")"
grep -q 'report.pdf' "$TMP/mem/sandbox/catalog/README.md" && fail "the index should not mention the PDF"
grep -q 'dump.mem' "$TMP/mem/sandbox/catalog/README.md" && fail "a failed probe should not leave a dump.mem row"
pass "vol is not started on a PDF leftover and a failed .mem probe is dropped"

# vol missing: note the memory file, not the PDF.
rm -f "$TMP/mem/bin/vol" "$TMP/mem/sandbox/catalog/README.md"
PATH="$hide:/usr/bin:/bin" bash "$ROOT/scripts/evidence-catalog.sh" "$TMP/mem/sandbox" >/dev/null
grep -q 'vol missing: no memory catalog for inputs/dump.mem' "$TMP/mem/sandbox/catalog/README.md" \
  || fail "missing vol should be noted for a .mem file: $(cat "$TMP/mem/sandbox/catalog/README.md")"
grep -q 'report.pdf' "$TMP/mem/sandbox/catalog/README.md" && fail "missing vol should not be noted for a PDF"
pass "vol missing is noted only for files that look like memory"

# The probe timeout, not the 900s step timeout, bounds windows.info.
mkdir -p "$TMP/slow/bin" "$TMP/slow/sandbox/inputs"
dd if=/dev/zero of="$TMP/slow/sandbox/inputs/dump.mem" bs=1024 count=64 status=none
printf '%s\n' '#!/usr/bin/env bash' 'exit 1' > "$TMP/slow/bin/mmls"
cp "$TMP/slow/bin/mmls" "$TMP/slow/bin/fsstat"
cat > "$TMP/slow/bin/vol" <<'EOF'
#!/usr/bin/env bash
sleep 30
echo NTBuildLab
exit 0
EOF
chmod +x "$TMP/slow/bin/vol" "$TMP/slow/bin/mmls" "$TMP/slow/bin/fsstat"
start=$(date +%s)
PATH="$TMP/slow/bin:/usr/bin:/bin" SWARM_CATALOG_MEMORY_PROBE_TIMEOUT=1 \
  bash "$ROOT/scripts/evidence-catalog.sh" "$TMP/slow/sandbox" >/dev/null
elapsed=$(( $(date +%s) - start ))
[[ "$elapsed" -lt 15 ]] || fail "memory probe should give up in ~1s, took ${elapsed}s"
[[ ! -d "$TMP/slow/sandbox/catalog/dump.mem" ]] \
  || fail "a timed-out probe should not keep a catalog tree"
pass "windows.info is time-boxed by the memory probe, not the 900s step timeout"

# --- segmented images are one image ------------------------------------------
# libewf resolves a whole set from any segment, so cataloguing .E02 repeats
# .E01's work exactly. The BelkaCTF #6 run catalogued one 8.7 GB disk six
# times before this rule existed.
eval "$(sed -n '/^is_continuation_segment()/,/^}/p' "$ROOT/scripts/evidence-catalog.sh")"
[[ "$(type -t is_continuation_segment)" == function ]] || fail "is_continuation_segment missing"

SEG="$(mktemp -d)"
trap 'rm -rf "$SEG"' EXIT
: > "$SEG/disk.E01"; : > "$SEG/disk.E02"; : > "$SEG/disk.E10"; : > "$SEG/disk.EAA"
: > "$SEG/raw.001"; : > "$SEG/raw.002"
: > "$SEG/orphan.002"
: > "$SEG/mem.raw"
: > "$SEG/case.Ex01"; : > "$SEG/case.Ex02"

is_continuation_segment "$SEG/disk.E01" >/dev/null && fail "the first segment is not a continuation"
is_continuation_segment "$SEG/raw.001" >/dev/null && fail "the first split-raw segment is not a continuation"
is_continuation_segment "$SEG/case.Ex01" >/dev/null && fail "EnCase 7's first segment is not a continuation"
is_continuation_segment "$SEG/mem.raw" >/dev/null && fail "a plain image is not a continuation"
is_continuation_segment "$SEG/orphan.002" >/dev/null && fail "a .002 with no .001 beside it stands on its own"
for f in disk.E02 disk.E10 disk.EAA raw.002 case.Ex02; do
  is_continuation_segment "$SEG/$f" >/dev/null || fail "$f should be a continuation of its set"
done
[[ "$(is_continuation_segment "$SEG/disk.EAA")" == "disk.E01" ]] \
  || fail "a continuation names the set's first segment"
pass "a segment set is catalogued once: continuations are named, not walked"

# And end to end: two segments in, one catalogue out, with the skip on the record.
SEGSB="$(mktemp -d)"
mkdir -p "$SEGSB/inputs"
head -c 200000 /dev/zero > "$SEGSB/inputs/disk.E01"
head -c 200000 /dev/zero > "$SEGSB/inputs/disk.E02"
bash "$ROOT/scripts/evidence-catalog.sh" "$SEGSB" >/dev/null
grep -q "1 further segment(s)" "$SEGSB/catalog/README.md" \
  || fail "the index should say a segment was skipped: $(cat "$SEGSB/catalog/README.md")"
grep -q "disk.E01" "$SEGSB/catalog/README.md" \
  || fail "the index should name the set's first segment"
[[ ! -d "$SEGSB/catalog/disk.E02" ]] || fail "disk.E02 should not have its own catalog tree"
rm -rf "$SEGSB"
pass "the catalog index names the segments it did not walk, and why"
