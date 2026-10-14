---
id: snapshots/chain-integrity
title: Is the disk or snapshot chain whole?
when: A VM's disk is a snapshot, delta or differencing disk, or a backing chain must be established.
needs: []
tools: [snapshot_chain_check]
requires_host: [qemu-img, target-query]
---

Use when a disk may depend on a parent or an earlier snapshot, and you need to say whether the set you hold is whole. Not for a disk's content (`filesystem/layers` of the base pack) or for guessing what a missing parent held.

1. **Collect the set** before reading anything: every descriptor, every extent the descriptors name, every parent, the `.vmx` and `.vmsd`, and the lock or state files beside them. Hash them. A chain is judged over the files you hold.
2. **Run `snapshot_chain_check` on the directory.** It reads VMware descriptors, VHD, VHDX and QCOW2 headers (not disk content) and prints each disk, each parent edge, each descriptor extent, and each chain from a leaf to its base. It never opens a name a file contains; a parent outside the set is reported missing.
3. **Read each edge.** `resolved_to` is the parent found; `id_check` is `match`, `mismatch` or `not_available`. VMDK compares the child's recorded parent CID with the parent's CID; VHD, its parent unique id; VHDX, its parent linkage with the parent's disk id. QCOW2 records no identity of its backing file, so only its name links it: say that, and do not call a QCOW2 chain verified by identity.
4. **Chain statuses:** `complete` (every named parent present, identities agree where recorded), `broken` (a parent not in the set), `identity_mismatch` (the child was made against a different parent file, or the parent changed afterwards), `cycle`, `too_deep`. A `mismatch` means the chain cannot be trusted as one history until the cause is shown.
5. **Extents.** `missing` or `short` extents mean the disk cannot be read whole from this set. Do not infer the file was deleted: it may not have been collected.
6. **Optional second reading.** `qemu_img: auto` runs `qemu-img info` once per image on a copy and keeps its answer beside the tool's; disagreement is a question. The base pack lists `qemu-img` as optional: if the image lacks it, the answer says so, and the native reading stands. `qemu-img info --backing-chain` is an examiner's command on a copy in a job with no network; it follows names the image holds. Read guest content only after the chain is established, with `target-query` (Dissect) or the base pack's layer skill.
7. **Never repair.** `qemu-img commit`, `rebase`, `convert` or a hypervisor's consolidate on evidence changes the chain. Work on copies.

**Shows.** The files' own statements about their parents, and whether the set satisfies them. **Does not show.** That the disk boots, what the parent held when the child was made, or why a parent is absent.
**Record.** The chain per leaf, each edge's resolution and id check, missing extents, hashes, tool and version, qemu-img's answer or its absence.
**Sensitive output.** Names and hints are shape-checked, not secret-proof: run as a job with `secret_output: true`.
