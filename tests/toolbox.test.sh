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

# A Python library is present when its import works, whatever its name: the
# probe used to be honoured for three names only, so pybde, pyvhdi, pytsk3
# and dfvfs were listed missing on a host that had them.
cat > "$TMP/bin/python3" <<'PYFAKE'
#!/usr/bin/env bash
[[ "${1:-}" == "--version" ]] && { echo "Python 3.12.0"; exit 0; }
if [[ "${1:-}" == "-c" ]]; then
  case "${2:-}" in
    *"import pybde"*|*"import pyvhdi"*|*"import pyvshadow"*|*"import pyvslvm"*) echo "20240101"; exit 0 ;;
  esac
fi
exit 1
PYFAKE
chmod +x "$TMP/bin/python3"
for b in vshadowinfo xfs_db vslvminfo; do printf '#!/usr/bin/env bash\necho "%s 20240101"\n' "$b" > "$TMP/bin/$b"; chmod +x "$TMP/bin/$b"; done
rm -f "$TMP/sb/toolbox.json"
bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" crypto,linux >/dev/null 2>&1 || true
for n in pybde pyvhdi pyvshadow pyvslvm vshadowinfo xfs_db vslvminfo; do
  jq -e --arg n "$n" '.present[] | select(.name == $n)' "$TMP/sb/toolbox.json" >/dev/null \
    || fail "$n is on this host but toolbox.json does not list it present: $(jq -c '.missing | map(.name)' "$TMP/sb/toolbox.json")"
done
jq -e '.missing[] | select(.name == "pytsk3")' "$TMP/sb/toolbox.json" >/dev/null \
  || fail "pytsk3 cannot be imported here and should be missing"
pass "python libraries are probed by import, and the VSS, XFS and LVM readers are checked"

# Each reader is in the set that its cases ask for, and only there.
rm -f "$TMP/sb/toolbox.json"
bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" crypto >/dev/null 2>&1 || true
names="$(jq -r '[.present[], .missing[]] | map(.name) | join(" ")' "$TMP/sb/toolbox.json")"
[[ " $names " == *" vshadowinfo "* && " $names " == *" pyvshadow "* ]] || fail "the crypto set should check libvshadow: $names"
[[ " $names " == *" xfs_db "* || " $names " == *" vslvminfo "* ]] && fail "XFS and LVM readers belong to the linux set: $names"
rm -f "$TMP/sb/toolbox.json"
bash "$ROOT/scripts/toolbox.sh" "$TMP/sb" linux >/dev/null 2>&1 || true
names="$(jq -r '[.present[], .missing[]] | map(.name) | join(" ")' "$TMP/sb/toolbox.json")"
[[ " $names " == *" xfs_db "* && " $names " == *" vslvminfo "* && " $names " == *" pyvslvm "* ]] || fail "the linux set should check xfsprogs and libvslvm: $names"
[[ " $names " == *" vshadowinfo "* ]] && fail "libvshadow belongs to the crypto set: $names"
pass "libvshadow is in the crypto set; xfsprogs and libvslvm are in the linux set"
