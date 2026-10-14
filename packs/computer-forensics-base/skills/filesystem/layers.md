---
id: filesystem/layers
title: Layered storage and historical states
when: A container, split set, volume manager, encryption layer or snapshot sits between you and the files.
needs: []
tools: [image_layout, file_type]
requires_host: [mmls, fsstat, img_stat, img_cat, qemu-img, fsapfsinfo, target-query]
---

Use when the evidence is a virtual disk, a split set, a volume manager's member, an encrypted volume or has snapshots. Not for offset arithmetic once the volume is found (`evidence/imaging`) or telling encryption from damage (`filesystem/encrypted`).

An offset means something only inside one address space. Walk the layers in order and note which one each number belongs to: container, backing chain, device set, partition table, encryption, mapping layer (LVM, dynamic disk, Storage Space, RAID), file system, snapshot.

**Container.** `file_type` and `image_layout` name it from its first bytes (a candidate, not a validation); `file_type` also says whether they agree with the extension, only a claim by whoever named the file:

    raw, dd, .img, .001      the bytes of a disk or volume
    E01, Ex01, L01           EnCase: compressed, with an acquisition record; physical, volume or (L01) logical
    AFF, AFF4                two different formats; AFF4 is a zip-based container
    VHD, VHDX, VMDK, QCOW2   a virtual disk with its own header, possibly a backing chain and snapshots
    AD1                      FTK Imager's logical image: files, no volume (`evidence/ad1`)
    a directory or a zip     a collection, not an image (`evidence/collections`)

Inventory every segment, descriptor, extent and backing file before parsing; record the state you read. A split E01 is one image: give the first segment. A split raw set is not: give the Sleuth Kit every segment in order (the first alone ends early); `image_layout` reads one path.

**Virtual disks.** `qemu-img info --backing-chain` shows the chain and the snapshots (plain `info` only the immediate backing file). When `mmls` and `fsstat` open the container, their offsets are sectors of the virtual disk. Convert (`qemu-img convert -O raw`) only when the next tool cannot open it, to a separate output, and record the state chosen, the options and the output's size and digest. `img_stat` prints size and format as the Sleuth Kit reads it, the bound for any scan over all of it; `img_cat -s <first> -e <last>` writes a decoded range.

**Mapping layers.** `mmls` names the slot but `fsstat` cannot read it: the file system starts inside a logical volume whose metadata is at the front of the member. Rebuild it from that metadata and all the members with a reader that supports the layer: `target-query` (dissect; it also opens E01, VMDK, QCOW and a collection behind one interface, with a plugin per artefact family) or the Linux pack's `filesystem/storage` when loaded; check the version the image carries. A signature inside a member is a candidate, not the extent mapping. Validate the geometry, the metadata's consistency and that files read before accepting the volume. A missing member is a limitation.

**APFS.** `fsapfsinfo` reads a container's structure; snapshots, Fusion drives and T2-based encryption are not supported, so a failure there is the reader's limit. Whether the Sleuth Kit reads APFS is a fact of its build: try `fsstat`, record `mmls -V` (`filesystem/apfs`, macOS pack, when loaded).

A snapshot, shadow copy or earlier backing layer is a separate source with its own time: say which state each result is.

**Record.** Each layer passed, its identity, the tool and version, the offset in its own units, the sector size, what was missing.

**Does not show.** That an unread layer holds nothing, or that a reconstructed volume is the one the system used.
