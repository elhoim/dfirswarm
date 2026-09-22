---
id: processes/injection
title: Processes, and code that is not where it should be
when: You need what was running, or whether something was injected into it.
needs: [triage/what-you-have]
tools: [mem_fs]
requires_host: [memprocfs, vol]
---

With a framework on the host, the process tree is one command and the questions
worth asking of it are these.

**Parentage that makes no sense.** `winword.exe` with a child `cmd.exe`,
`services.exe` with a child that is not a service, an `svchost.exe` whose parent
is not `services.exe`, or two `lsass.exe`. Parent process ids are reused, so
check the parent's own start time is earlier than the child's before you build a
story on it.

**A path that is not the real one.** `svchost.exe` running from
`C:\Users\Public` rather than `System32`, or a name one character from a system
binary. Compare the full image path, not the process name.

**Memory that should not be executable.** A private, committed region marked
read-write-execute with a PE header at its start is injected code, and it is the
strongest single indicator in memory. Reflectively loaded modules have no entry
in the module list at all, which is why a module list that looks clean does not
settle the question.

**Handles and modules tell you what it reached.** A process holding a handle to
`lsass.exe` with read rights, or a named pipe it did not create, is worth more
than its command line.

With MemProcFS these are files: mount the image and the process tree,
per-process memory map, handles and modules are directories you can read with
the ordinary tools. `mem_fs` drives it and returns the listing. With Volatility
they are plugins, and you should record the version and the plugin name beside
every result — plugin output changes between versions and a reviewer has to be
able to reproduce it.

Whichever you used, **dump the region and hash it** before you call something
injected. A claim about memory that cannot be re-extracted is not checkable.
