# Accounts and registry / event log findings

Agent: sf4b201

## Scope and sources

Primary sources extracted from the NTFS image (`inputs/s4a-challenge4`, offset 2048):

- `Windows/System32/config/SAM` — inode `18491-128-3`
- `Windows/System32/config/SYSTEM` — inode `18499-128-3`
- `Windows/System32/config/SECURITY` — inode `18493-128-3`
- `Windows/System32/winevt/Logs/Security.evtx` — inode `42093-128-4`
- `Windows/System32/winevt/Logs/System.evtx` — inode `42091-128-4`

Extraction commands:

```bash
icat -o 2048 inputs/s4a-challenge4 18491-128-3 > work/sf4b201/hives/SAM
icat -o 2048 inputs/s4a-challenge4 18499-128-3 > work/sf4b201/hives/SYSTEM
icat -o 2048 inputs/s4a-challenge4 18493-128-3 > work/sf4b201/hives/SECURITY
icat -o 2048 inputs/s4a-challenge4 42093-128-4 > work/sf4b201/evtx/Security.evtx
icat -o 2048 inputs/s4a-challenge4 42091-128-4 > work/sf4b201/evtx/System.evtx
```

Parsing used `python3` + `regipy` for registry and `python-evtx` / forged tool `evtx_filter` for EVTX.

## Local accounts identified in the SAM hive

Default/built-in local accounts present:

- `Administrator` — RID `500`
- `Guest` — RID `501`

Additional local accounts present in `SAM\Domains\Account\Users\Names` and corresponding RID keys:

- `user1` — RID `1005`
  - `Names\user1` last write: `2015-09-02T09:05:06.019610+00:00`
  - `Users\000003ED` last write: `2015-09-02T09:05:06.019610+00:00`
  - Password last set: `2015-09-02T09:05:06.019610+00:00`
- `hacker` — RID `1006`
  - `Names\hacker` last write: `2015-09-02T09:05:25.378984+00:00`
  - `Users\000003EE` last write: `2015-09-02T09:05:25.378984+00:00`
  - Password last set: `2015-09-02T09:05:25.378985+00:00`

Interpretation: `user1` and `hacker` are non-default local accounts added by the attacker or during the compromise window. Their timestamps are much later than the built-in account timestamps and align with attack-period activity.

## Group membership evidence

The local machine SID from the SAM hive is:

- `S-1-5-21-3848053756-3249532031-1848221756`

Relevant built-in alias findings from `SAM\Domains\Builtin\Aliases`:

- `Users` alias (`00000221`) last write: `2015-09-02T09:05:25.410236+00:00`
  - Contains SIDs ending in `-1005` and `-1006`
- `Remote Desktop Users` alias (`0000022B`) last write: `2015-09-02T09:19:24.083848+00:00`
  - Contains SIDs ending in `-1005` and `-1006`

Interpretation: both attacker-added accounts were local users and were also added to the local `Remote Desktop Users` group. That later group-change timestamp suggests a persistence / remote-access step happened after the account creation step.

## Terminal Services / RDP state

From the extracted `SYSTEM` hive (`ControlSet001\Control\Terminal Server`):

- Key last write: `2015-09-12T18:18:22.798250+00:00`
- `fDenyTSConnections = 1`
- `TSUserEnabled = 0`
- `AllowRemoteRPC = 1`

From `ControlSet001\Services\TermService`:

- Service `Start = 2` (automatic)
- Service key last write: `2008-01-19T11:37:29.809143+00:00`

Interpretation: the attacker clearly granted `user1` and `hacker` membership in `Remote Desktop Users`, but the current SYSTEM hive still shows Remote Desktop connections denied (`fDenyTSConnections = 1`). So the evidence supports an **attempted or prepared RDP persistence path**, not a proven successful enablement of inbound RDP.

## Security event log findings

### Relevant logon / authentication events

Confirmed from `Security.evtx`:

- `2015-08-23T10:53:26Z` — four failed NTLM network logon attempts (event `4625`, record IDs `452`-`455`) for username `Student` from workstation `IT104-3`, IP `10.20.0.118`.
- Multiple successful local interactive/logon-unlock events for `Administrator` are present, including:
  - `2015-09-02T09:00:57.175859+00:00` — event `4624`, record `481`, `Administrator`, logon type `2`
  - `2015-09-02T09:17:06.974474+00:00` — event `4624`, record `492`, `Administrator`, logon type `7`
- Repeated `4672` privileged logons accompany `Administrator` logons.

### Not observed in the extracted Security/System logs

I did **not** find the expected account-management / service-install event IDs in the extracted logs:

- Security `4720` (user created)
- Security `4732` (member added to local group)
- System `7045` (service installed)

So, for the added accounts and their RDP-group membership, the current proof is strongest in the SAM hive itself rather than in explicit Security audit records.

## Point-in-time sequence supported by current evidence

1. `2015-09-02T09:05:06Z` — local account `user1` appears in SAM (RID `1005`).
2. `2015-09-02T09:05:25Z` — local account `hacker` appears in SAM (RID `1006`).
3. `2015-09-02T09:05:25Z` — `Users` alias reflects membership for RIDs `1005` and `1006`.
4. `2015-09-02T09:19:21Z` — Apache `access.log` shows remote host `192.168.56.102` POSTing to DVWA's command-execution endpoint `/dvwa/vulnerabilities/exec/`.
5. `2015-09-02T09:19:24Z` — `Remote Desktop Users` alias is modified and contains RIDs `1005` and `1006`.
6. `2015-09-02T09:28:30Z` — memory evidence shows an interactive `cmd.exe` (`PID 1972`, parent `explorer.exe`) in the Administrator session.

## Preliminary answer for report question 2

- The attacker added **2 local user accounts**: `user1` and `hacker`.
- They were added as local SAM accounts, then added to `Remote Desktop Users`.
- The **most likely method** was remote command execution through DVWA from `192.168.56.102`, because Apache `access.log` shows POSTs to `/dvwa/vulnerabilities/exec/` within seconds of the SAM account/group writes and no Prefetch-backed GUI admin artifacts were found.
- Exact creation command line for the **successful** 2015-09-02 account creation is still **not directly recovered** from my sources: explicit `4720` / `4732` audit events are absent, and neither disk nor memory has yielded the literal `net user` / `net localgroup` command for those successful changes.
- Separate evidence from Apache/PHP error logging shows the attacker later used web-shell command execution on **2015-09-03** and attempted `net user /add`, but those attempts failed Windows password policy (`NET HELPMSG 2245`). Those failed attempts should not be confused with the earlier successful creation of `user1` and `hacker` on 2015-09-02.

## Evidence snippets / parsing notes

User/RID mapping was confirmed by decoding the `V` values under these keys:

- `SAM\Domains\Account\Users\000003ED` → `user1`
- `SAM\Domains\Account\Users\000003EE` → `hacker`

And by reading the `Names` subkeys:

- `SAM\Domains\Account\Users\Names\user1`
- `SAM\Domains\Account\Users\Names\hacker`

Machine SID was derived from the SAM hive as:

- `S-1-5-21-3848053756-3249532031-1848221756`

That SID namespace was then used to identify the new-user SIDs embedded in built-in alias membership data.

## Cross-seat corroboration

Other seats materially strengthen the "how were they added" answer:

- Apache `access.log` (`inode 59684`) shows `192.168.56.102` POSTing to `/dvwa/vulnerabilities/exec/` at `2015-09-02T09:05:22Z`, which brackets the SAM creation of `user1` (`09:05:06Z`) and `hacker` (`09:05:25Z`).
- The same log shows another POST to `/dvwa/vulnerabilities/exec/` at `2015-09-02T09:19:21Z`, three seconds before the `Remote Desktop Users` alias write at `09:19:24Z`.
- `catalog/memdump.mem/pslist.txt` shows a later `cmd.exe` (`PID 1972`) created at `2015-09-02T09:28:30Z` under `explorer.exe`, consistent with hands-on command-shell activity in the Administrator session.
- `catalog/s4a-challenge4/p2048/timeline.csv` shows `Users/Administrator/AppData/Roaming/Microsoft/Internet Explorer/Quick Launch/Command Prompt.lnk` touched at `2015-09-02T09:18:32Z`, which is weak but supportive evidence of local command-prompt interaction.

Overall conclusion for Q2: the highest-confidence answer is **two users were added, and the additions were most likely driven through the exploited DVWA command-execution path from 192.168.56.102, then those accounts were added to Remote Desktop Users as a persistence step**.
