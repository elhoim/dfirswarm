---
id: windows/router
title: Windows notes by question
when: Pick one when none is listed, or you cannot choose.
router: true
mentions: [shellbags]
---

Use when the index shows only this line and you need a Windows note. Not for rules: each note holds its own.

Machine
`registry/system-profile` build, names
`registry/overview` hive state; `registry/readers` key reads; `registry/clock` zones
`accounts/logons` SIDs; `accounts/sessions` who

Ran
`execution/overview` which source
`execution/prefetch` `execution/prefetch-carved` `execution/amcache` `execution/shimcache` `execution/userassist` `execution/srum`
`execution/esedb` ESE tables

Files
`filesystem/mft` `filesystem/journals` USN; `filesystem/timestamps` NTFS; `filesystem/ads` `filesystem/indx` slack; `filesystem/recycle-bin`
`filesystem/deleted` recoverable?
`filesystem/shadowcopies` list; `filesystem/shadowcopies-open` read

Touched
`artifacts/shell` which to read
`artifacts/links` `artifacts/jumplists` `artifacts/shellbags`
`registry/devices` USB; `registry/devices-dates` USB dates

Logs
`logs/security` read .evtx; `logs/events` ids; `logs/coverage` absence
`logs/hunting` Sigma; `logs/carving` `logs/recovery` cleared
`logs/lateral` shares, services, WMI; `logs/remote-access` RDP
`logs/powershell` `logs/powershell-history`

Persist
`persistence/mechanisms` `persistence/tasks-com-wmi`

Browser
`browser/artefacts` `browser/downloads` `browser/webcache` `browser/strings` raw

Memory
`memory/windows` `memory/hibernation-pagefile`

Anti-forensics
`antiforensics/traces` `antiforensics/log-clearing` `antiforensics/controls` `antiforensics/timestamps-clock` `antiforensics/wiping`
