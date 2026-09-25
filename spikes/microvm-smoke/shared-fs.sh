#!/usr/bin/env bash
# Three VMs, one read-write host directory: do the filesystem guarantees the
# swarm protocol leans on (exclusive create, flock, O_APPEND, atomic rename,
# visibility, change notification) hold between agents in different VMs?
#
#   bash shared-fs.sh WORKDIR [ROUNDS]
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
W=${1:?usage: shared-fs.sh WORKDIR [ROUNDS]}
N=${2:-200}
IMG=${IMAGE:-dfirswarm-base:dev-arm64}
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) PLAT=darwin-arm64 ;; Linux-x86_64) PLAT=linux-x64-gnu ;; *) exit 2 ;;
esac
export PATH="$HERE/node_modules/@superradcompany/microsandbox-$PLAT/bin:$PATH"
VMS=(shfs-a shfs-b shfs-c)
cleanup() { for v in "${VMS[@]}"; do msb stop "$v" >/dev/null 2>&1; msb rm "$v" >/dev/null 2>&1; done; }
trap cleanup EXIT

mkdir -p "$W" && W=$(cd "$W" && pwd -P)
S="$W/shared"; rm -rf "$S"; mkdir -p "$S"
for v in "${VMS[@]}"; do
  msb create "$IMG" --name "$v" --no-net --mount-dir "$S:/shared" \
    --mount-file "$HERE/guest-shared.py:/opt/gs.py:ro" > "$W/create-$v.log" 2>&1
done
msb ls | grep shfs- | awk '{print $1, $3}'
run_all() {  # mode, then per-VM extra args
  local mode=$1; shift
  local pids=() i=0
  for v in "${VMS[@]}"; do
    msb exec "$v" -- python3 /opt/gs.py "$mode" /shared "$v" "$N" "$@" > "$W/$mode-$v.out" 2>&1 &
    pids+=($!); i=$((i + 1))
  done
  wait "${pids[@]}"
  cat "$W/$mode"-*.out
}

echo; echo "== excl: O_CREAT|O_EXCL lock, $N rounds x 3 VMs"
echo 0 > "$S/counter"; run_all excl
echo "counter $(cat "$S/counter") (expected $((3 * N)))"

echo; echo "== flock: $N rounds x 3 VMs"
echo 0 > "$S/counter"; run_all flock
echo "counter $(cat "$S/counter") (expected $((3 * N)))"

echo; echo "== append: $N lines x 3 VMs, 3 KB each, O_APPEND"
rm -f "$S/appended.log"; run_all append >/dev/null
python3 - "$S/appended.log" "$N" <<'EOF'
import sys
lines = open(sys.argv[1], "rb").read().split(b"\n")[:-1]
bad = [l for l in lines if b"|" not in l or len(l.rsplit(b"|", 1)[0]) != int(l.rsplit(b"|", 1)[1] or 0)]
print(f"{len(lines)} lines (expected {3 * int(sys.argv[2])}), {len(bad)} torn or interleaved")
EOF

echo; echo "== rename: one writer, two readers"
rm -f "$S/current" "$S"/.tmp-*
msb exec shfs-a -- python3 /opt/gs.py rename /shared writer-a "$N" > "$W/rename-a.out" 2>&1 &
p1=$!
msb exec shfs-b -- python3 /opt/gs.py rename /shared reader-b "$N" > "$W/rename-b.out" 2>&1 &
p2=$!
msb exec shfs-c -- python3 /opt/gs.py rename /shared reader-c "$N" > "$W/rename-c.out" 2>&1 &
p3=$!
wait $p1 $p2 $p3; cat "$W"/rename-*.out

echo; echo "== see: how long until each VM sees the others' new files"
rm -f "$S"/seen-*
run_all see "shfs-a,shfs-b,shfs-c" | cat

echo; echo "== inotify in VM a while VM b and the host write"
rm -f "$S"/from-*
msb exec shfs-a -- python3 /opt/gs.py inotify /shared shfs-a > "$W/inotify.out" 2>&1 &
pw=$!
sleep 3
msb exec shfs-b -- sh -c 'echo hi > /shared/from-vm-b' >/dev/null 2>&1
echo hi > "$S/from-host"
msb exec shfs-a -- sh -c 'echo self > /shared/from-vm-a-itself' >/dev/null 2>&1
wait $pw; cat "$W/inotify.out"

echo; echo "== host sees VM writes, with ownership as the host shows it"
ls -ln "$S" | awk 'NR>1 {print $3":"$4, $1, $9}' | sort | uniq -c | head -8
