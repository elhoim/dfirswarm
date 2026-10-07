---
id: persistence/mechanisms
title: Examining persistence configuration and activation evidence
when: You need to identify supported persistence mechanisms and distinguish configuration from execution.
needs: [registry/overview, logs/security]
tools: [regkv, evtx_query, icat_extract, file_type, mft_records, ioc_scan]
requires_host: [fls, RECmd, regripper]
---

Sweep by family and record, for each one, what you examined. A configured mechanism
is a configuration: that it was set up, and that it fired, are separate findings.
Read hives by the rules of `registry/overview` (control set, dirty hive, key-level
last-write times). A recovered file or script is read, hashed and compared; it is
never run.

**Services and drivers.** `SYSTEM\ControlSet00n\Services\<name>`: record the control
set, service name, `Type`, `Start` (0 boot, 1 system, 2 automatic, 3 on demand, 4
disabled), the account in `ObjectName`, `ImagePath` (arguments included),
`Parameters\ServiceDll` for a hosted service, failure-action and trigger
configuration, and the identity of the file they name (`icat_extract` returns its
sha256, `file_type` what it is). Many legitimate components live under the Windows
directory, so a directory alone is not a finding: look for configuration that does
not fit the component it claims to be, a name that imitates one, a file that is not
what its name says, and an account or start mode out of line with its peers. The
key's last-write time dates a change to the key, not the install. Correlate with
the install and change events of `logs/security` (7045, 4697, 7040) and with
execution evidence; a missing install event may reflect retention or collection,
not the absence of the service.

**Run and startup locations.** Examine, in `SOFTWARE` (and its 32-bit view under
`Wow6432Node`) and in each `NTUSER.DAT`:

    ...\CurrentVersion\Run   RunOnce      Policies\Explorer\Run
    ...\CurrentVersion\Explorer\User Shell Folders   Shell Folders   (Startup, Common Startup)

The Startup folders are the paths those values resolve to for the user and for all
users; list them with `fls` on the image and extract what is there. `RunServices`
and `RunServicesOnce` are legacy and version-specific: record them where present
and do not assume the build reads them. Winlogon (`Shell`, `Userinit`), image file
execution options (`Debugger`), `AppInit_DLLs` (with `LoadAppInit_DLLs`) and the
other logon-time settings take effect only under conditions of the build and
policy: establish the referenced component, and the condition, before you call one
active.

**Scheduled tasks.** Compare three records. The task files under
`Windows/System32/Tasks/` (XML) hold triggers, actions, principals and the enabled
state; the `TaskCache` `Tree` and `Tasks` keys under
`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule` hold the registry side; the
Security events of `logs/security` (4698, 4699) show creation and deletion where the
audit was on. The `Author` and date fields are metadata the creator supplied. The
binary values (`Actions`, `Triggers`, `DynamicInfo`) come back from `regkv` as hex
and are not decoded in this pack; name the decoder if you read one. A task in one
place and not the other is a finding to report with both sides: do not name a cause
(deletion, cleanup, partial collection and tampering all produce it).

**COM and WMI.** A per-user COM registration (`Software\Classes\CLSID\...\InprocServer32`
and the like) is stored in that user's `UsrClass.dat`, not in `NTUSER.DAT`; record
the server path and whether the same CLSID is registered machine-wide. WMI event
subscriptions live in the WMI repository (`Windows/System32/wbem/Repository`),
which this pack does not decode: record it as not examined. A text search of its
files with `ioc_scan` gives locators for consumer class names, not a decoded
subscription; add the events of the `WMI-Activity/Operational` channel where the
image has it (`evtx_query`; for example 5861, a permanent subscription binding).

**Replaced or redirected system binaries.** For a suspected substitution of a
system program (the login-screen accessibility programs among them), compare the
recovered file with a trusted reference for the exact build (one from the case or
from vendor media; this pack carries none), and record its hash, signature and
version metadata, size, owner and permissions where the image keeps them, and its
file system history (`mft_records`, `filesystem/mft`, `filesystem/journals`): servicing
rewrites system files too. File replacement and registry redirection are different
hypotheses; check both. A matching hash identifies bytes. It does not show the
mechanism, the actor or that the substitute was used.

**Activation.** To say a mechanism ran, find an execution record that fits its
trigger and times: Prefetch, Amcache, SRUM, process-creation events with their
parent, service state events (`execution/overview`). Say what the record would
look like if the mechanism had not fired. For an independent sweep, `RECmd` batch
files or `regripper` plugins (where the image carries them; record the plugin or
batch file and its version) are a second reader; neither replaces the keys above.

**Bounded negatives.** If nothing is identified, state the result over what was
examined: "No persistence mechanism was identified in <families>, <hives and
profiles>, <task files>, <period>", with the families, profiles and stores that were
unavailable or unsupported (the WMI repository, a user whose hive was not
collected, a dirty hive that was not replayed). Do not conclude that no persistence
existed, and do not infer what an operator meant to do.

**Sensitive output.** A Run value, a service `ImagePath` or a task's arguments can
carry a typed secret. `regkv` withholds values whose name says password, secret,
token or credential, but not a secret inside a command line: describe the command's
shape, and never write the secret, a fragment of it or a hash of it. Run
`evtx_query` as a job with `secret_output: true` when the log may hold command lines.

**Does not show.** A persistence entry does not show that it ran, who set it, when it
was set (a key's last-write time is key-level), or why. No entry does not show that
none existed.
