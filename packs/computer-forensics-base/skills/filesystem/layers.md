---
id: filesystem/layers
title: Layered storage and historical states
when: A container, split set, volume manager, encryption layer or snapshot sits between you and the files.
needs: []
tools: [image_layout, file_type]
requires_host: [mmls, fsstat, img_stat, img_cat, qemu-img, fsapfsinfo, target-query]
---

Use when the evidence is a virtual disk, a split set, a volume manager's member, an encrypted volume or has snapshots. Not for offset arithmetic once the volume is found (`evidence/imaging`) or telling encryption from damage (`filesystem/encrypted`).

An offset means something only inside one address space. Walk the layers in order and write down which one each number belongs to: container, backing chain, device set, partition table, encryption, mapping layer (LVM, dynamic disk, Storage Space, RAID), file system, snapshot.

**Container.** `file_type` and `image_layout` name it from its first bytes (a candidate, not a validation):

    raw, dd, .img, .001      the bytes of a disk or volume
    E01, Ex01, L01           EnCase: compressed, with an acquisition record; physical, volume or (L01) logical
    AFF, AFF4                two different formats
    VHD, VHDX, VMDK, QCOW2   a virtual disk with its own header, possibly a backing chain and snapshots
    AD1                      FTK Imager's logical image: files, no volume (`evidence/ad1`)

Inventory every segment, descriptor, extent and backing file before parsing; record the state you read. A split E01 is one image: give the first segment. A split raw set is not: the Sleuth Kit takes every segment in order on its command line (the first alone ends early); `image_layout` reads one path.

**Virtual disks.** `qemu-img info` shows the backing chain and snapshots. If `mmls` and `fsstat` open the container, their offsets are sectors of the virtual disk. Convert (`qemu-img convert -O raw`) only when the next tool cannot open it, to a separate output; record the layers, the state chosen, the tool, version, options, and the output's size and digest. `img_stat` prints the size and format as the Sleuth Kit reads it; `img_cat -s <first> -e <last>` writes a decoded range.

**Mapping layers.** `mmls` names the slot but `fsstat` cannot read it: the file system starts inside a logical volume whose metadata is at the front of the member. Reconstruct it from that metadata and all the members with a reader that supports the layer (`target-query`, or the Linux pack's `filesystem/storage` when loaded; check its version). A file system signature inside a member is a candidate, not the extent mapping. Validate the geometry and that files read before accepting the volume. A missing member is a limitation.

**APFS.** `fsapfsinfo` reads a container's structure; snapshots, Fusion drives and T2-based encryption are not supported (its declaration here), so a failure there is the reader's limit. Whether the installed Sleuth Kit reads APFS is a fact of its build: try `fsstat`, record `mmls -V` (`filesystem/apfs`, macOS pack, when loaded).

A snapshot, shadow copy or earlier backing layer is a separate source with its own time: say which state each result is.

**Record.** Each layer passed, its identity, the tool and version, the offset in its own units, the sector size, what was missing.

**Does not show.** That an unread layer holds nothing, or that a reconstructed volume is the one the system used.
