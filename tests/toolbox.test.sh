#!/usr/bin/env bash
# The crypto set's aescrypt row is pyAesCrypt, not a PATH binary named aescrypt.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok - $*"; }

TMP="$(mktemp -d "${TMPDIR:-/tmp}/toolbox.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/sb"

# python3 answers the pyAesCrypt probe; nothing named aescrypt is on PATH.
cat > "$TMP/bin/python3" <<'EOF'
#!/usr/bin/env bash
if [[ "${1:-}" == "--version" ]]; then
  echo "Python 3.12.0"
  exit 0
fi
if [[ "${1:-}" == "-c" ]]; then
  case "${2:-}" in
    *pyAesCrypt*) echo "pyAesCrypt ok"; exit 0 ;;
  esac
  exit 1
fi
exit 1
EOF
chmod +x "$TMP/bin/python3"
command -v jq >/dev/null || fail "jq required"
ln -s "$(command -v jq)" "$TMP/bin/jq"

# Keep the usual shell tools, but never an aescrypt binary.
PATH="$TMP/bin:/usr/bin:/bin"
command -v aescrypt >/dev/null 2>&1 && fail "this test needs a PATH with no aescrypt binary"

bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" crypto >/dev/null
jq -e '.present[] | select(.name == "aescrypt")' "$TMP/sb/toolbox.json" >/dev/null \
  || fail "pyAesCrypt is installed (the probe succeeded) but aescrypt was listed missing: $(cat "$TMP/sb/toolbox.json")"
jq -e '.missing[] | select(.name == "aescrypt")' "$TMP/sb/toolbox.json" >/dev/null \
  && fail "aescrypt must not be missing when import pyAesCrypt works"
pass "toolbox crypto treats pyAesCrypt as aescrypt, without a PATH binary"

# And when the import fails, it is missing — --toolbox-required is a BLOCKER.
cat > "$TMP/bin/python3" <<'EOF'
#!/usr/bin/env bash
[[ "${1:-}" == "--version" ]] && { echo "Python 3.12.0"; exit 0; }
exit 1
EOF
chmod +x "$TMP/bin/python3"
rm -f "$TMP/sb/toolbox.json"
set +e
out="$(bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" crypto --required 2>&1)"
rc=$?
set -e
[[ "$rc" -eq 3 ]] || fail "missing pyAesCrypt with --required should exit 3, got $rc: $out"
printf '%s\n' "$out" | grep -q "aescrypt" || fail "the BLOCKER should name aescrypt: $out"
jq -e '.missing[] | select(.name == "aescrypt")' "$TMP/sb/toolbox.json" >/dev/null \
  || fail "toolbox.json should list aescrypt as missing when the import fails"
pass "toolbox crypto reports aescrypt missing when pyAesCrypt cannot be imported"
