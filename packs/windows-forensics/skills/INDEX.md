# Skills in this pack

Fetch a body with `skill("<id>")`. A body may name others; fetch those the same way.

- `accounts/logons` Accounts, logon sessions and attribution limits: You need to associate activity with an account or session and assess whether human attribution is supported.
- `antiforensics/traces` Investigating possible evidence removal or manipulation: Artefacts are missing or inconsistent and you need to distinguish deliberate action from ordinary retention, configuration or collection limits.
- `artifacts/shell` Links, Jump Lists, ShellBags and recent-item records: You need to interpret shell references to files, directories, volumes or shares without overstating user activity.
- `browser/artefacts` Browser records, visits and download provenance: You need to examine browser profiles, navigation records or downloads and distinguish them from background or synchronized activity.
- `execution/amcache` Amcache and ShimCache inventory and interpretation: You need to identify a file or interpret compatibility and application-inventory records.
- `execution/overview` Assessing evidence of program execution: You need to distinguish file presence, launch, account context and completed activity.
- `execution/prefetch` Prefetch structure, launch history and limitations: You need to interpret a Prefetch file or carved candidate using a parser validated for its format.
- `execution/srum` SRUM resource accounting and network-use limits: You need to interpret application resource records, byte counts and their aggregation and attribution limits.
- `execution/userassist` UserAssist, BAM and DAM activity records: You need to decode profile- or SID-associated application activity and assess its coverage.
- `filesystem/ads` Named NTFS data streams and their interpretation: You need to enumerate and extract alternate streams or assess evidence of their use.
- `filesystem/deleted` Deleted content, Recycle Bin records and recovery limits: You need to evaluate deletion evidence and recoverability within the acquired sources.
- `filesystem/journals` NTFS change-journal and transaction-log evidence: You need to interpret retained changes, file identities and source-local ordering.
- `filesystem/mft` MFT records, timestamps, streams and index remnants: You need to examine NTFS metadata and distinguish current, historical, reused and partially decoded records.
- `filesystem/shadowcopies` Volume shadow copies and historical source states: You need to enumerate available snapshots or compare an artefact across observed volume states.
- `logs/hunting` Rule-based event review and detection coverage: You need to search collected logs with a documented ruleset and interpret matches and bounded negatives.
- `logs/powershell` PowerShell logs, script blocks and interactive history: You need to interpret retained PowerShell content, invocation context and logging limits.
- `logs/recovery` Recovering and qualifying damaged or residual event records: A log is cleared, damaged or incomplete and other acquired sources may retain records.
- `logs/remote-access` Remote-access records and cross-host correlation: You need to distinguish authentication, session activity and remote operations across supplied hosts.
- `logs/security` Windows event schemas, authentication and audit coverage: You need to interpret event records with their provider, outcome, configuration and retention context.
- `memory/windows` Windows memory examination and capability checks: You have a memory-related source and need to establish its format, available analysis routes and limitations.
- `persistence/mechanisms` Examining persistence configuration and activation evidence: You need to identify supported persistence mechanisms and distinguish configuration from execution.
- `registry/devices` Device identities, mount associations and connection records: You need to correlate removable-device observations without equating attachment with transfer.
- `registry/overview` Registry sources, recovery state and interpretation: You need to select, validate and query an offline hive while preserving state and timestamp meaning.
- `registry/system-profile` Windows build, volume, profile and clock context: You need to establish the system context required to interpret other Windows artefacts.
