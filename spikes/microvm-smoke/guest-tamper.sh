#!/bin/sh
# Runs as root inside the VM. Tries every way we know to change evidence that
# the host mounted read-only, and says what each attempt did. The verdict is
# not taken from this output: the host compares its own fingerprints.
#
#   /evidence  host directory over virtio-fs, mounted ro,noexec
#   /ev2       host ext4 image over virtio-blk, mounted ro

try() {
  name="$1"; shift
  if out=$( "$@" 2>&1 ); then
    echo "SUCCEEDED  $name"
  else
    echo "blocked    $name: $(printf '%s' "$out" | tail -1)"
  fi
}

py_write() { python3 -c "f=open('$1','r+b'); f.seek(0); f.write(b'TAMPERED'); f.flush(); import os; os.fsync(f.fileno())"; }
py_xattr() { python3 -c "import os; os.setxattr('$1', 'user.tamper', b'1')"; }

echo "== whoami: $(id -u) / kernel $(uname -r)"
echo "== mounts"
grep -E ' /evidence | /ev2 ' /proc/mounts

echo "== virtio-fs directory, as mounted (ro)"
try "append to notes.txt"        sh -c 'echo TAMPERED >> /evidence/notes.txt'
try "create a new file"          sh -c 'echo x > /evidence/planted.txt'
try "delete notes.txt"           rm -f /evidence/notes.txt
try "chmod notes.txt"            chmod 777 /evidence/notes.txt
try "backdate mtime"             touch -d 2000-01-01 /evidence/notes.txt
try "truncate blob.bin"          truncate -s 0 /evidence/blob.bin
try "rename sub/a.bin"           mv /evidence/sub/a.bin /evidence/sub/b.bin
try "mkdir"                      mkdir /evidence/newdir
try "python r+b write"           py_write /evidence/notes.txt
try "set xattr"                  py_xattr /evidence/notes.txt
try "execute tool.sh directly"   /evidence/tool.sh
try "execute via interpreter"    sh /evidence/tool.sh

echo "== virtio-fs directory, after remount rw"
try "mount -o remount,rw"        mount -o remount,rw /evidence
grep ' /evidence ' /proc/mounts
try "append after remount"       sh -c 'echo TAMPERED >> /evidence/notes.txt'
try "create after remount"       sh -c 'echo x > /evidence/planted.txt'
try "truncate after remount"     truncate -s 0 /evidence/blob.bin
try "delete after remount"       rm -f /evidence/sub/a.bin

echo "== virtio-fs directory, the same share mounted again read-write"
tag=$(awk '$2 == "/evidence" { print $1 }' /proc/mounts)
mkdir -p /mnt/evrw
try "mount tag $tag rw"          mount -t virtiofs "$tag" /mnt/evrw
grep ' /mnt/evrw ' /proc/mounts
try "append via rw mount"        sh -c 'echo TAMPERED >> /mnt/evrw/notes.txt'
try "create via rw mount"        sh -c 'echo x > /mnt/evrw/planted.txt'
try "python write via rw mount"  py_write /mnt/evrw/notes.txt

echo "== virtio-blk ext4 image, as mounted (ro)"
dev=$(awk '$2 == "/ev2" { print $1 }' /proc/mounts)
echo "device: $dev  ro-flag: $(cat /sys/block/$(basename "$dev")/ro 2>/dev/null)"
try "append in /ev2"             sh -c 'echo TAMPERED >> /ev2/docs/ledger.txt'
try "remount /ev2 rw"            mount -o remount,rw /ev2
try "append after remount"       sh -c 'echo TAMPERED >> /ev2/docs/ledger.txt'
try "blockdev --setrw"           blockdev --setrw "$dev"
try "dd onto the device"         dd if=/dev/zero of="$dev" bs=4096 count=16 seek=64 conv=notrunc,fsync
try "python write to the device" py_write "$dev"
mkdir -p /mnt/blk
try "mount the device rw again"  mount -t ext4 -o rw "$dev" /mnt/blk
try "append via second mount"    sh -c 'echo TAMPERED >> /mnt/blk/docs/ledger.txt'
sync
echo "== done"
