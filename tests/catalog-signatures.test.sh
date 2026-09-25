#!/usr/bin/env bash
# The kickoff's warning about an encrypted or virtual volume in the catalog:
# a VM run whose packs include encrypted-containers already has the readers
# in its image and is not told to start again with that pack.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/catsig.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/sb/catalog/disk.E01/p2048"
printf 'Users/alice/Documents/desktop.ini:vault.vhdx\n' > "$TMP/sb/catalog/disk.E01/p2048/filelist.txt"

eval "$(sed -n '/^warn_on_catalog_signatures()/,/^}/p' "$ROOT/scripts/swarm.sh")"

isolation=microvm
out="$(warn_on_catalog_signatures "$TMP/sb" "" "windows-forensics" 2>&1)"
grep -q 'start again with --pack encrypted-containers' <<<"$out" \
  || fail "a VM run without encrypted-containers should be told to add it: $out"
out="$(warn_on_catalog_signatures "$TMP/sb" "" "windows-forensics,encrypted-containers,mobile-forensics" 2>&1)"
[[ -z "$out" ]] || fail "a VM run with encrypted-containers was told to start again with it: $out"
pass "a VM run is told to add encrypted-containers only when it does not have it"

isolation=host
out="$(warn_on_catalog_signatures "$TMP/sb" "dfir" "encrypted-containers" 2>&1)"
grep -q 'no crypto toolbox set' <<<"$out" || fail "a host run without the crypto set should still be warned: $out"
out="$(warn_on_catalog_signatures "$TMP/sb" "dfir,crypto" "" 2>&1)"
[[ -z "$out" ]] || fail "a host run with the crypto set was warned: $out"
pass "a host run is warned by its toolbox sets, as before"
