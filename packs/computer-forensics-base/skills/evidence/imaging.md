---
id: evidence/imaging
title: Find the volume and its offset
when: Before listing a disk or volume, or diagnosing an unreadable source.
needs: []
tools: [image_layout]
requires_host: [mmls, fsstat, ewfinfo, img_stat]
---

Use when you must list a disk or volume, or an image will not read. Not for the container formats, virtual disks, split sets, mapping layers and APFS (`filesystem/layers`).

Most wasted hours start here: a command run against the whole image instead of a volume inside it, or an offset in the wrong unit. Offsets mean something only inside a defined address space, so know which one you are in.

Run `image_layout` once per image and put its output on the board. It names the container from its signature, reads an E01's acquisition record (`ewfinfo`), runs `mmls` and `fsstat`, and returns each volume's offset in sectors and bytes. Treat it as a probe: `partition_table` is true (mmls read one), false (mmls ran and recognised none: that does not show there is none) or `unknown` (mmls was missing, timed out or was refused, mmls failed without saying why and `img_stat` does not open the image, or `img_stat` says the Sleuth Kit opened a VHD, QCOW2 or other container as raw, so its offsets belong to the container's bytes: convert or attach it first, `filesystem/layers`). The programs' whole output is kept in files (`raw_outputs`); preserve it for any layout you rely on.

**Then find the volume.** `mmls` prints the partition table in sectors, and the Sleuth Kit's `-o` also takes sectors: pass the number `mmls` printed and do not multiply it. Read the sector size rather than assuming it: `mmls` says it in its header (`Units are in N-byte sectors`), `fsstat` prints it per volume, and `-b` tells the toolkit when it cannot work it out. Pass the same `-b` to every command on the image; `image_layout` does when you give it `sector_size`, and returns the commands with it.

    mmls image.E01                      # the table, with the sector offset per slot
    fsstat -o 2048 image.E01            # confirm: type, cluster size, volume serial

Shapes that are not a mistake and need another move:

- **No partition table.** A single volume imaged alone. Drop `-o`. `mmls` finding none is an answer about those bytes at that sector size, not a broken image.
- **A mapping layer** (LVM, a dynamic disk, a Storage Space, RAID): `mmls` names the slot but `fsstat` cannot read it. Do not rebuild it from a signature: `filesystem/layers`.
- **An unallocated gap.** It may never have held a partition. Describe a deleted partition only when other metadata supports it; its content, not its size, is the evidence.

**A logical collection is not an image.** A directory of copied files or an AD1 has no partition table to read: see `evidence/collections`.

**An unreadable volume is an observation, not a diagnosis.** Record the exact failure, and treat incomplete segments, wrong geometry, an unsupported format or feature, a missing mapping layer or backing data, encryption and corruption as separate hypotheses. Unreadability alone establishes none of them. `filesystem/encrypted` says what a positive encryption indicator looks like.

**Does not show.** A partition table shows the layout as it was last written, not what the disk held. A file system that `fsstat` parses is not shown intact, complete or unencrypted at the file level.
