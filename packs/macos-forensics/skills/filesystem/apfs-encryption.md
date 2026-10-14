---
id: filesystem/apfs-encryption
title: APFS encryption, FileVault and hardware limits
when: An APFS volume is unreadable or FileVault state is in question.
needs: []
tools: []
requires_host: []
mentions: [fvdeinfo]
---

Use only if a volume is unreadable or the question is FileVault or hardware-bound encryption. Not for acquired volumes and snapshots (`filesystem/apfs`).

Separate legacy Core Storage FileVault from an encrypted APFS volume, and Intel without a T2 chip from Intel with one and from Apple silicon. An unreadable volume or a FileVault preference does not show the key state, and hardware-bound encryption can leave a raw acquisition unreadable even with some credentials in hand. `fvdeinfo` is for Core Storage; it is not assumed to read APFS. Use an acquisition and parser documented for the hardware, filesystem and encryption state; if the encrypted-containers pack is loaded, its skill index says which skill carries the FileVault route. Any step that handles credentials is a `secret_output` job inside the case's authority and offline.

Shows: that a volume is unreadable by the reader used, and which encryption family the evidence names. Does not show: the key state, that the data is unrecoverable, or that a FileVault preference means a volume was encrypted.
Record: the hardware generation, the encryption family, the reader and its version, and the authority for any credential step.
Sensitive output: key material and recovery keys are never written, in part or as a hash; a credential step runs as a `secret_output` job.
