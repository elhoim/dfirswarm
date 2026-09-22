---
id: triage/what-you-have
title: What the container is, before anything else
when: The evidence includes a memory image, a crash dump or a hibernation file.
needs: [evidence/verify]
tools: [mem_profile]
requires_host: []
---

Memory arrives in half a dozen containers and they are not interchangeable.
Naming the wrong one wastes an hour and produces a framework error that reads
like a corrupt image.

    raw / .mem / .dmp from a hypervisor   physical memory, nothing around it
    .vmem beside a .vmsn                  VMware, and the snapshot holds the rest
    Windows crash dump                    PAGEDU64 or PAGEDUMP magic, with a header
                                          listing the physical memory runs
    hiberfil.sys                          HIBR or a zeroed header; compressed, and a
                                          PAST state, not the state at acquisition
    LiME / AVML                           Linux, with their own framing
    ELF core                              from a hypervisor or a process dump

Run `mem_profile` first. It reads the header, names the container, reports the
size and the page count, and where the format says so, the memory runs and the
build the dump came from.

Three consequences that change the whole examination:

1. **A crash dump is not contiguous physical memory.** Its header lists runs
   with gaps between them, and a tool that treats the file as flat reads the
   wrong offsets for everything after the first gap.
2. **`hiberfil.sys` is a past state and it is compressed.** That is what makes
   it valuable — it is the machine before the operator cleaned up — but you must
   say in the report which moment you are quoting, and it is not the moment of
   acquisition.
3. **A `.vmem` on its own is missing the CPU state** that lives in the `.vmsn`.
   Carving and string work are unaffected; anything that needs the page tables
   may not be.

Then check the evidence is what you were handed, with `check_inputs`, and only
then start. See `evidence/verify` in the base pack.
