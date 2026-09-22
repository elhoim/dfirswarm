---
id: persistence/mechanisms
title: Where something arranges to run again
when: You have a payload and need to know how it survives a reboot, or you are sweeping for one.
needs: [registry/overview, logs/security]
tools: [regkv, evtx_query]
requires_host: [icat, fls]
---

Sweep these in order. The first three carry most real cases.

**Services.** `SYSTEM\ControlSet00n\Services\<name>`: `ImagePath`, `Start`
(2 is automatic, 3 demand), the account under `ObjectName`. Pair every candidate
with System event 7045 for the install and 7040 for a start-type change. A
service whose display name impersonates a platform component, running from
`C:\Windows\` rather than from a vendor directory, is the shape to look for.

**Run keys.** In both `SOFTWARE` and each `NTUSER.DAT`:

    ...\CurrentVersion\Run  RunOnce  RunServices  RunServicesOnce
    ...\CurrentVersion\Explorer\Shell Folders\Startup

**Scheduled tasks.** `Windows/System32/Tasks/` holds one XML file per task with
its trigger, its action and its author. The registry mirror is under
`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`.

Then the quieter ones: `Winlogon` `Shell` and `Userinit`, image file execution
options with a `Debugger` value, `AppInit_DLLs`, WMI event subscriptions under
`root\subscription`, COM hijacks in `HKCU\Software\Classes\CLSID`, and
accessibility binaries replaced on disk.

That last one has no registry footprint at all. A login-screen accessibility
tool replaced by a copy of the command shell gives a system prompt before anyone
logs in, and the only evidence is that the file's hash equals the shell's. It
was the whole answer to one published case. Hash the accessibility binaries.

When you find none of these, say so. A payload with no persistence is a finding:
it says the operator expected to return another way, or did not need to.
