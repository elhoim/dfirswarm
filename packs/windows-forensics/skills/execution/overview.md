---
id: execution/overview
title: Assessing evidence of program execution
when: You need to distinguish file presence, launch, account context and completed activity.
needs: [registry/overview]
tools: []
requires_host: []
---

This is a method skill and names no tool: the readers are in the skills it points
to. Its job is to make you say which claim a source supports before you cite it.

**Name the claim first.** "The file was on the machine", "a process started", "it
ran to completion", "it did something", "an account's session started it", "a
person chose to" are six claims, and each source below supports some of them and
not the others. Write the claim, then the source, then the step between them.

| Source | What it records | Skill |
| --- | --- | --- |
| Prefetch | an application-launch record for one executable path, with files the prefetcher referenced | `execution/prefetch` |
| UserAssist | shell-associated activity in one profile's hive | `execution/userassist` |
| BAM and DAM | per-SID last-execution values, where the build keeps them | `execution/userassist` |
| Amcache | an inventory of applications and files (presence) | `execution/amcache` |
| ShimCache | an observation by the compatibility cache | `execution/amcache` |
| SRUM | aggregated resource accounting | `execution/srum` |
| Event 4688, Sysmon 1 | process creation, when collected and configured | `logs/security` |
| PowerShell 4104 | script-block content that was logged | `logs/powershell` |
| A shadow copy | an earlier state of a source, not another execution mechanism | `filesystem/shadowcopies` |

The pack has no decoder for UserAssist, BAM/DAM or ShimCache values: read them as
bytes and say the method (`execution/userassist`, `execution/amcache`).

Event 4688 and Sysmon event 1 exist only where auditing or the Sysmon service was
installed and configured before the event: record the provider, its version and its
configuration with the record (`logs/security`).

**Weigh evidence by what it can support, not by a fixed ranking or a count.** A
valid process-creation record that parsed cleanly can establish that a process
started; it does not establish that its intended action completed. One well-supported
record can stand. Three artefacts that share an origin (the same hive, a copy in a
shadow copy, parsers that share a decoder) are one source. When a conclusion is
material, look for a source that does not depend on the first, and say what the
two do and do not have in common.

**Their clocks differ.** Each source has its own epoch, zone, resolution and event: a
launch recorded by the prefetcher, a shell launch, a per-SID last-run value and an
inventory write are not one moment. Do not reconcile them to the second without
saying what each timestamp is. Say the clock and zone of each.

**A renamed or relocated executable.** Identify a binary by its content hash where
the bytes exist, and correlate file references, rename history, cached paths and
process records. A name or a path in an artefact is a label the artefact carries.
If the bytes are gone, say the identification is an inference and keep the
alternatives.

**Say which mechanism you are claiming** (started from the shell, by a service, by a
task, by another process) and which account: an account or SID is a context, not a
person (`accounts/logons`).

**Absence is bounded.** Write "No evidence of execution of X was found in <sources>,
<interval>", and say the detection opportunity: was the source enabled and
configured, does its retained interval cover the time, was it acquired whole and
parsed without partial results (`status`), and could it have been altered or
cleared. A missing Prefetch file is not an execution negative until the build, the
prefetcher's configuration, its service state and the collection are established;
do not infer them from a Server edition or an SSD.

**Does not show.** From any single execution artefact: who operated the machine,
that the program finished or had an effect, that it was the only run, or that a
program with no entry did not run.
