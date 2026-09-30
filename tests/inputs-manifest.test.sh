#!/usr/bin/env bash
# scripts/inputs-manifest.ts against the Python program it replaces
# (tests/fixtures/inputs-manifest-oracle.py, kept verbatim): over the same
# evidence, each writes the same inputs.json byte for byte (but the time it
# was written and how long the content check took), the same problems on
# stderr and the same exit status. The evidence covers every kind of name
# the walk meets:
# - nested directories, names that sort differently by code point than by
#   UTF-16 unit, both Unicode forms of a name, and a name that is not UTF-8
#   where the volume allows one;
# - links to a file and to a directory, a broken link, a FIFO;
# - a copy, a copy with sets, in place and an image;
# - a copy short a file, with a file extra, with a size or the content
#   changed.
# No model, no Herdr, no VM.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/inputs-manifest.XXXXXX")"
trap 'chmod -R u+w "$TMP" 2>/dev/null; rm -rf "$TMP"' EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

# The evidence: every kind of name the walk meets.
make_evidence() { # <dir>
  local d="$1"
  mkdir -p "$d/logs/old" "$d/Docs" "$d/zeta"
  printf 'alpha\n' > "$d/a.txt"
  printf 'Bravo\n' > "$d/B.txt"
  : > "$d/empty.bin"
  printf 'line 1\nline 2\n' > "$d/logs/syslog"
  printf 'rotated' | gzip -c > "$d/logs/old/syslog.1.gz"
  printf 'quote "and" back\\slash\n' > "$d/Docs/quote \"and\" back\\slash.txt"
  printf 'é composed\n' > "$d/Docs/$(printf 'caf\xc3\xa9').txt"
  printf 'é decomposed\n' > "$d/Docs/$(printf 'cafe\xcc\x81') 2.txt"
  printf 'astral\n' > "$d/zeta/$(printf '\xf0\x9f\x98\x80').txt"
  printf 'fullwidth\n' > "$d/zeta/$(printf '\xef\xbc\x81').txt"
  printf 'tab\n' > "$d/zeta/$(printf 'tab\there').txt"
  # Links below the top (a top-level link is copied as what it names, and checked so).
  ln -s ../a.txt "$d/Docs/link-to-file"
  ln -s ../logs "$d/Docs/link-to-dir"
  ln -s missing "$d/Docs/broken-link"
  mkfifo "$d/logs/pipe"
  # A name that is not UTF-8 (Latin-1 é): only where the volume takes one.
  (printf 'latin\n' > "$d/Docs/$(printf 'caf\xe9')-latin1.txt") 2>/dev/null || true
}

# Runs both writers over a sandbox and compares their manifests, stderr and exit status.
compare() { # <label> <sandbox> <args...>
  local label="$1" sb="$2"; shift 2
  local py_rc=0 ts_rc=0
  python3 "$ROOT/tests/fixtures/inputs-manifest-oracle.py" "$sb" "$@" 2> "$TMP/py.err" || py_rc=$?
  [[ -f "$sb/inputs.json" ]] || fail "$label: the oracle wrote no inputs.json ($(cat "$TMP/py.err"))"
  mv "$sb/inputs.json" "$TMP/py.json"
  node --experimental-strip-types --no-warnings "$ROOT/scripts/inputs-manifest.ts" "$sb" "$@" 2> "$TMP/ts.err" || ts_rc=$?
  [[ -f "$sb/inputs.json" ]] || fail "$label: inputs-manifest.ts wrote no inputs.json ($(cat "$TMP/ts.err"))"
  mv "$sb/inputs.json" "$TMP/ts.json"
  # What only the clock decides: when it was written, and how long the content check took.
  for f in py ts; do
    sed -E -e 's/("copied_at": )"[^"]*"/\1"T"/' -e 's/("seconds": )[0-9.e+-]+/\1S/' "$TMP/$f.json" > "$TMP/$f.norm"
  done
  cmp -s "$TMP/py.norm" "$TMP/ts.norm" || { diff "$TMP/py.norm" "$TMP/ts.norm" | head -20 >&2; fail "$label: the manifests differ"; }
  grep -q '"seconds": [0-9]*\.[0-9]' "$TMP/ts.json" || ! grep -q '"seconds"' "$TMP/py.json" || fail "$label: the content check's seconds is not written as a float"
  [[ "$py_rc" == "$ts_rc" ]] || fail "$label: exit $py_rc from the oracle, $ts_rc from inputs-manifest.ts"
  cmp -s "$TMP/py.err" "$TMP/ts.err" || { diff "$TMP/py.err" "$TMP/ts.err" | head -20 >&2; fail "$label: stderr differs"; }
  pass "$label: the same manifest, stderr and exit status ($ts_rc)"
}

SRC="$TMP/source"
make_evidence "$SRC"
nonutf8=0
ls "$SRC/Docs" | LC_ALL=C grep -q $'\xe9-latin1' && nonutf8=1

echo "# a copy: every kind of name, verified by content"
SB="$TMP/copy"; mkdir -p "$SB"; cp -a "$SRC" "$SB/inputs"
compare "copy" "$SB" "$SRC" on on copy 1 0
grep -q '"special": "fifo"' "$TMP/ts.json" || fail "the FIFO is not recorded by its kind"
grep -q '"link": "../logs"' "$TMP/ts.json" || fail "the link to a directory is not recorded as a link"
[[ "$nonutf8" == 0 ]] || grep -q '"path_b64"' "$TMP/ts.json" || fail "the non-UTF-8 name has no path_b64"

echo "# a copy checked by names only, quarantined"
compare "copy, names only" "$SB" "$SRC" on off copy 0 1

echo "# a copy short a file, with a file extra, with a size changed"
SB="$TMP/short"; mkdir -p "$SB"; cp -a "$SRC" "$SB/inputs"
rm "$SB/inputs/B.txt"; printf 'extra\n' > "$SB/inputs/extra.txt"; printf 'alpha, longer\n' > "$SB/inputs/a.txt"
compare "a mismatched copy" "$SB" "$SRC" on on copy 1 0
[[ "$(grep -c '' "$TMP/ts.err")" -ge 4 ]] || fail "the mismatch is not said"

echo "# a copy whose content changed, same size"
SB="$TMP/content"; mkdir -p "$SB"; cp -a "$SRC" "$SB/inputs"
printf 'ALPHA\n' > "$SB/inputs/a.txt"
compare "a copy differing by content" "$SB" "$SRC" on on copy 1 0
grep -q "differs from its source by content: inputs/a.txt" "$TMP/ts.err" || fail "the content mismatch is not named"

echo "# a copy in sets"
SRC2="$TMP/source2"; mkdir -p "$SRC2/sub"; printf 'two\n' > "$SRC2/sub/two.txt"; printf 'root two\n' > "$SRC2/r.txt"
SB="$TMP/sets"; mkdir -p "$SB/inputs"; cp -a "$SRC" "$SB/inputs/disk"; cp -a "$SRC2" "$SB/inputs/phone"
compare "a copy in two sets" "$SB" "" on on copy 1 0 disk "$SRC" phone "$SRC2"
grep -q '"name": "phone"' "$TMP/ts.json" || fail "the sets are not named"

echo "# a top-level link in the copy where the source holds what it names"
SB="$TMP/toplink"; mkdir -p "$SB"; cp -a "$SRC2" "$SB/inputs"; rm "$SB/inputs/r.txt"; ln -s sub/two.txt "$SB/inputs/r.txt"
compare "a top-level link in the copy" "$SB" "$SRC2" on on copy 0 0

echo "# the evidence in place, and in sets in place"
SB="$TMP/bind"; mkdir -p "$SB"; ln -s "$SRC" "$SB/inputs"
compare "in place" "$SB" "$SRC" on on bind 0 0
grep -q '"mode": "' "$TMP/ts.json" || fail "a bound file has no mode"
SB="$TMP/bindsets"; mkdir -p "$SB/inputs"; ln -s "$SRC" "$SB/inputs/disk"; ln -s "$SRC2" "$SB/inputs/phone"
compare "in place, in sets" "$SB" "" on on bind 0 0 disk "$SRC" phone "$SRC2"

echo "# an attached image"
SB="$TMP/image"; mkdir -p "$SB/inputs"; cp -a "$SRC2/." "$SB/inputs/"
compare "an image" "$SB" "$SRC2" on image image 0 0

echo "# an earlier read-only manifest is replaced"
SB="$TMP/readonly"; mkdir -p "$SB"; cp -a "$SRC2" "$SB/inputs"; printf '{}\n' > "$SB/inputs.json"; chmod a-w "$SB/inputs.json"
node --experimental-strip-types --no-warnings "$ROOT/scripts/inputs-manifest.ts" "$SB" "$SRC2" on on copy 0 0 || fail "a read-only manifest was not replaced"
grep -q '"held": "copy"' "$SB/inputs.json" || fail "the read-only manifest was not rewritten"
pass "a read-only manifest from an earlier kickoff is replaced"
