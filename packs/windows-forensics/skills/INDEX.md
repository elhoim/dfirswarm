# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

- `accounts/logons` Accounts, who they are, and who was actually at the keyboard: Attributing an action to a person.
- `antiforensics/traces` What hiding leaves behind: The evidence looks too clean, or a first pass found nothing.
- `artifacts/shell` Link files, jump lists, shell bags and recent documents: What a user opened, from where, and whether the source was removable or a share.
- `browser/artefacts` Browsers, and proving what a person looked at: Policy violation, phishing, download provenance, or a search that started the case.
- `execution/amcache` Amcache and ShimCache, and what they do not prove: You need a hash for a binary that is gone, or a list of what was on the machine.
- `execution/overview` Proving a program ran, and how much each artefact is worth: Any claim that something was executed.
- `execution/prefetch` Prefetch, and the compressed format: You need a run count, a last run time, or what a binary loaded.
- `execution/srum` SRUM, for what a program did on the network: You need bytes moved, or a program's activity by the hour.
- `execution/userassist` UserAssist, BAM and DAM: You must tie an execution to a specific user.
- `filesystem/ads` Alternate data streams, and execution from them: Something is hidden, or a listing shows a file whose size does not match its contents.
- `filesystem/deleted` Deleted files, the recycle bin, and wiped files: Files are missing, or you must say whether they are recoverable.
- `filesystem/journals` The change journal and the log file: Something was deleted or renamed and you need to prove it happened, and when.
- `filesystem/mft` The master file table, and what a record proves: You need a file's true times, its size, whether it was deleted, or what a directory used to hold.
- `filesystem/shadowcopies` Volume shadow copies, and the volume as it was last week: A file, a hive or a log is missing, cleaned or too recent; or before you conclude anything is gone.
- `logs/hunting` Hunting with rules, and what a detection is worth: The first pass found nothing, or the logs are too large to read by event id.
- `logs/powershell` PowerShell, and what survives an operator who tried to leave nothing: A command line, a downloader, a disabled defence, or anything an interactive attacker did.
- `logs/recovery` Reading a log that was cleared: Security 1102 or System 104 is present, a channel is empty, or the log file is truncated.
- `logs/remote-access` Remote access and lateral movement: Someone reached this machine from another one, or left it for another one.
- `logs/security` The event logs, and the records that carry weight: Logons, account changes, service installs, log clearing, or anything with a time.
- `memory/windows` A Windows memory image, with or without a framework: The evidence includes a .mem, .raw, .vmem, hiberfil.sys or a crash dump.
- `persistence/mechanisms` Where something arranges to run again: You have a payload and need to know how it survives a reboot, or you are sweeping for one.
- `registry/devices` USB and removable devices: Data may have left on a stick, or a device is part of the story.
- `registry/overview` The hives, where they live, and how to read one: Any question about configuration, accounts, devices, execution or persistence.
- `registry/system-profile` Build the system profile before anything else: The first ten minutes of any Windows case.
