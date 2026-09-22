---
id: evidence/verify
title: Prove the evidence is what you were handed, and that it stays that way
when: Before the first command of any case, and again before you write the report.
needs: []
tools: [check_inputs]
requires_host: []
---

Do this before anything else. A finding from evidence you cannot prove was
unchanged is not a finding.

1. Read `inputs.json`. It carries every file under `inputs/`, its size and its
   sha256, taken when the run copied or bound the evidence.
2. Compare the acquisition record if the case shipped one. Images usually travel
   with a `.txt` or `.csv` from the imager holding its own MD5 or SHA-1, and an
   E01 carries the record inside it, which `image_layout` returns. Quote the
   imager's digest and yours separately in the report. They cover different
   things: the imager hashed the source, you hashed the container.
3. Run `check_inputs` now. Run it again before you write the report. Both runs
   land on the trace as `inputs_check` and the report's custody section reads
   them.

`inputs/` is held read-only by the kernel wherever the host can do it. You
cannot write there and you should not try: a refusal is recorded as a violation
against your name. Work in `work/`.

The container is not the volume. An E01 holds a logical image; its own digest is
not the digest of the file system inside it. When you quote a hash, say which
one it is.

If the run was started with the evidence bound in place rather than copied, the
paths under `inputs/` are a view of the operator's own directory. Same rule,
more care: nothing you do may write there.
