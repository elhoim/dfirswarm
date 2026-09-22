#!/usr/bin/env bash
# The evidence catalog under --inputs-bind. There inputs/ is a symlink to the
# operator's directory, and a walk that stops at the link catalogs nothing: on
# run s3091 a 25 GB disk image and a 1 GB memory dump were reported as
# "0 disk image(s), 0 memory image(s)" while the copied runs of the same case
# found both. What broke was the walk, so that is what this holds still: the
# files the catalog considers must be the same through a link as through a copy.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
fail() { echo "FAIL: $*" >&2; exit 1; }

src="$tmp/evidence"; mkdir -p "$src/logs"
head -c 70000 /dev/urandom > "$src/disk.raw"
echo "a line" > "$src/logs/access.log"
copy="$tmp/copy"; mkdir -p "$copy"; cp -R "$src" "$copy/inputs"     # as --inputs makes it
bind="$tmp/bind"; mkdir -p "$bind"; ln -s "$src" "$bind/inputs"      # as --inputs-bind makes it

rel() { bash "$ROOT/scripts/evidence-catalog.sh" --candidates "$1" | sed "s#^$1/inputs/##"; }
copied="$(rel "$copy")"
bound="$(rel "$bind")"
echo "copy:"; printf '  %s\n' $copied
echo "bind:"; printf '  %s\n' $bound
[[ "$copied" == $'disk.raw\nlogs/access.log' ]] || fail "the copied tree was not walked in full: $copied"
[[ "$bound" == "$copied" ]] || fail "the catalog sees a different tree through the bind symlink"
# and the whole catalog still runs on a bound tree, ending in a summary line
bash "$ROOT/scripts/evidence-catalog.sh" "$bind" 2>&1 | grep -q 'Summary:' || fail "the catalog did not finish on a bound inputs/"
echo "ok - the catalog walks the same files through a bound inputs/ as through a copy"
