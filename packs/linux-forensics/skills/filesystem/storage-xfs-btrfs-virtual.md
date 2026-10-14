---
id: filesystem/storage-xfs-btrfs-virtual
title: XFS, Btrfs and virtual disk images
when: A volume is XFS or Btrfs, or the disk is a VDI, VMDK, QCOW2 or VHD file.
needs: []
tools: []
requires_host: [xfs_db, btrfs, qemu-img]
---

Use only if the filesystem is XFS or Btrfs or the disk is a virtual disk file. Not for the storage graph (`filesystem/storage`) or LVM and LUKS (`filesystem/storage-lvm-luks`).

- XFS: `xfs_db -r -c sb -c p <volume-copy>` reads read-only. Record the filesystem and inode versions, enabled features, allocation groups and any external log or realtime device. An XFS log is recovery metadata, not a record of user actions. Do not run XFS's repair program on evidence; even its no-modify mode is a diagnostic.
- Btrfs: `btrfs inspect-internal dump-super -f <volume-copy>` records devices and the generation. Inventory every supplied device, subvolume, snapshot and root id: the default subvolume is not the whole filesystem. Reflinks and snapshots share extents, and a generation orders changes without being a wall-clock time. Never mount Btrfs read-write for convenience.
- If the installed tool cannot enumerate or extract what the question needs, record that as a coverage gap.

For VDI, VMDK, QCOW2 and VHD, inspect a stable acquired copy with `qemu-img info --output=json --backing-chain <copy>` where the installed version supports it. Inventory and hash every backing file and relevant snapshot, and treat backing paths as untrusted metadata: resolve them only to supplied objects inside the examination scope. Use `--force-share` only when the need is stated, because it can read metadata that is changing under you. Convert only to a new file under work, never in place; a conversion is one derived view and does not show that every snapshot or backing layer was present. Keep the originals, the command, the errors and the mapping from source to output.

Shows: superblock and backing-chain metadata. Does not show: that a snapshot or backing layer was present in a conversion, or user actions from an XFS log. Record: versions, devices, subvolumes, backing files with hashes, the command and errors.

Sensitive output: none beyond paths; a converted image holds the whole disk, so keep it under work.
