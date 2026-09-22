# Accounts, registry, and event-log findings

## Scope and evidence

Primary evidence extracted from the NTFS volume at offset 2048 with `icat`:

- `inputs/s4a-challenge4` inode `18491-128-3` -> `work/sf6df01/extracted/registry/SAM` (`sha256 a449fbe404f9df69d48ff0a74bf988f8751147d4755f880a6056b7bc6735109d`)
- `inputs/s4a-challenge4` inode `18499-128-3` -> `work/sf6df01/extracted/registry/SYSTEM` (`sha256 fca4919725d8e350056cd1f9ef3d17f2902715995a9300bf193bea242936a513`)
- `inputs/s4a-challenge4` inode `18493-128-3` -> `work/sf6df01/extracted/registry/SECURITY` (`sha256 13bfff3baa50626b0054793dcacbe01090182dc0ec0aaa77f01df5e00182d78c`)
- `inputs/s4a-challenge4` inode `201-128-1` -> `work/sf6df01/extracted/registry/Administrator.NTUSER.DAT` (`sha256 0d2f3ca11ed002aaf68ff19cbe1973f01f79ecf13b986e1c81a253ec36ef0bae`)
- `inputs/s4a-challenge4` inode `42093-128-4` -> `work/sf6df01/extracted/evtx/Security.evtx` (`sha256 b8ed63be0c8be007664eab0803d3703c39ab0f4ef539e1eade35960d0f6534ef`)
- `inputs/s4a-challenge4` inode `42091-128-4` -> `work/sf6df01/extracted/evtx/System.evtx` (`sha256 aa7852b096881b955f7d24c2759506a5df70b1f337eaebb0e02f04b77c7aee6b`)
- `inputs/s4a-challenge4` inode `42092-128-4` -> `work/sf6df01/extracted/evtx/Application.evtx` (`sha256 69bf9ee1adb6abdf75369f97a99f50dffd2cc659d779ca9ac1ee08e0a66a33d6`)

Parsing outputs used below:

- `python3 work/sf6df01/parse_accounts.py` -> `work/sf6df01/parsed/sam_users.tsv`
- `python3 work/sf6df01/parse_accounts.py` -> `work/sf6df01/parsed/sam_memberships.tsv`
- `python3 work/sf6df01/parse_accounts.py` -> `work/sf6df01/parsed/ntuser_userassist_focus.tsv`
- `python3 work/sf6df01/parse_accounts.py` -> `work/sf6df01/parsed/account_timeline.tsv`
- `python3 ...` over `Security.evtx` -> `work/sf6df01/parsed/logon_type_summary.tsv`
- `grep -nE 'Users/(user1|hacker)(/|$)' catalog/s4a-challenge4/p2048/filelist.txt || echo NO_MATCH_FOR_user1_OR_hacker_PROFILE_DIRS` -> `work/sf6df01/parsed/user_profile_search.txt`
- `python3 ...` over `SYSTEM` hive `ControlSet001\Control\TimeZoneInformation` -> `work/sf6df01/parsed/timezone.txt`

## Findings summary

### 1) The host is a standalone/workgroup system using Pacific time

`Security.evtx` logon records identify the local account domain as `WIN-L0ZZQ76PMUF` and the machine/workgroup side as `WORKGROUP` (for example `Security.evtx` record IDs `480-482` at `2015-09-02 09:00:57 UTC`, preserved in `work/sf6df01/parsed/account_timeline.tsv`).

The SYSTEM hive key `ControlSet001\Control\TimeZoneInformation` shows `TimeZoneKeyName = Pacific Standard Time` and `ActiveTimeBias = 420`, i.e. UTC-7 at the time of interest (`work/sf6df01/parsed/timezone.txt`). This matches Apache's `-0700` timestamps used by the web-activity seats.

### 2) Two attacker-added local accounts are present: `user1` and `hacker`

`work/sf6df01/parsed/sam_users.tsv` shows only four local accounts in SAM:

- `Administrator` RID 500
- `Guest` RID 501
- `user1` RID 1005
- `hacker` RID 1006

The non-built-in accounts were created close together on 2015-09-02:

- `user1` SAM user key `\SAM\Domains\Account\Users\000003ED` last-write `2015-09-02T09:05:06.019610+00:00`; password set at the same timestamp.
- `hacker` SAM user key `\SAM\Domains\Account\Users\000003EE` last-write `2015-09-02T09:05:25.378984+00:00`; password set at the same timestamp.

Because these are the first non-built-in RIDs after 500/501 and their creation timestamps are sequential within 20 seconds, they are strong evidence of deliberate account creation by the intruder, not baseline OS setup.

### 3) Both attacker-added accounts were added to `Remote Desktop Users`, but not to `Administrators`

`work/sf6df01/parsed/sam_memberships.tsv` decodes the local built-in alias membership keys under:

`Builtin\Aliases\Members\S-1-5-21-3848053756-3249532031-1848221756\<RID>`

For the attacker-added accounts:

- `user1` RID 1005 membership key last-write `2015-09-02T09:18:09.021348+00:00` -> groups `Users` (RID 545) and `Remote Desktop Users` (RID 555)
- `hacker` RID 1006 membership key last-write `2015-09-02T09:19:24.083848+00:00` -> groups `Users` (RID 545) and `Remote Desktop Users` (RID 555)

For comparison:

- `Administrator` RID 500 is in `Administrators` (RID 544)
- neither `user1` nor `hacker` shows membership in `Administrators`

Interpretation: the attacker provisioned both new accounts for logon/RDP access, but did not persist by adding them to the local Administrators group.

### 4) The most likely creation method was the local Computer Management GUI (`CompMgmtLauncher.exe` / Local Users and Groups)

I do **not** have direct `4720` / `4732` records in the retained `Security.evtx`, so the method must be inferred carefully from adjacent artifacts.

Evidence chain:

1. `Security.evtx` records `478-482` show a failed `Administrator` local logon at `2015-09-02 09:00:39 UTC`, followed by a successful local interactive `Administrator` logon (`4624`, logon type `2`) at `2015-09-02 09:00:57 UTC`; see `work/sf6df01/parsed/account_timeline.tsv`.
2. `Administrator.NTUSER.DAT` UserAssist records show `UEME_RUNPATH:C:\Windows\system32\CompMgmtLauncher.exe` at `2015-09-02T09:01:02.519000+00:00`; see `work/sf6df01/parsed/ntuser_userassist_focus.tsv`.
3. The two accounts appear in SAM at `09:05:06` and `09:05:25 UTC` (`work/sf6df01/parsed/sam_users.tsv`).
4. Their `Remote Desktop Users` memberships are added later at `09:18:09` and `09:19:24 UTC` (`work/sf6df01/parsed/sam_memberships.tsv`).
5. `cmd.exe` does not appear in the same NTUSER UserAssist set until later, at `2015-09-02T09:28:30.411000+00:00`.

The timing strongly favors this sequence: a local `Administrator` session opened Computer Management, created `user1` and `hacker`, then added both to `Remote Desktop Users`. Because `cmd.exe` is only evidenced later, command-line creation via `net user` / `net localgroup` is **possible but less supported** than GUI-based creation.

### 5) No successful use of `user1` or `hacker` appears in the retained Security log

`work/sf6df01/parsed/logon_type_summary.tsv` shows successful `4624` logons only for:

- `Administrator` (types `2` and `7`)
- service identities `SYSTEM`, `LOCAL SERVICE`, `NETWORK SERVICE`, and `IUSR`
- anonymous network logons

There are **no** retained successful `4624` logons for `user1` or `hacker`, and no logon type `10` (RemoteInteractive/RDP) successes at all in the retained Security log.

Separately, `work/sf6df01/parsed/user_profile_search.txt` shows no `Users/user1` or `Users/hacker` profile directories in `catalog/s4a-challenge4/p2048/filelist.txt`. Together, these points suggest the attacker-created accounts were staged for access but were not used to create persistent local profiles before acquisition.

### 6) Relevant `Administrator` activity during the attack window

The retained Security log does capture repeated local `Administrator` unlock/logon activity around the intrusion window:

- `2015-09-03 06:49:13 UTC` records `527-530` (`4776`, `4648`, `4624` type `7`, `4672`)
- `2015-09-03 07:03:37 UTC` records `538-541` (`4776`, `4648`, `4624` type `7`, `4672`)
- `2015-09-03 10:02:53 UTC` records `552-555` (`4776`, `4648`, `4624` type `7`, `4672`)

These should be correlated with the web-shell uploads and command execution already found by the disk/web seats. I would treat them as evidence that the host had an active local `Administrator` desktop session during the broader compromise window.

### 7) Important limitations of the retained event logs

The retained logs do **not** contain the event IDs we would ideally cite directly for account creation / group change / service install:

- `Security.evtx` parsed event IDs present: `4616, 4624, 4625, 4634, 4647, 4648, 4672, 4717, 4776`
- `System.evtx` parsed event IDs present: `1074, 1076, 6005, 6006, 6008, 7040`
- therefore no retained `4720`, no retained `4732`, and no retained `7045`

This is preserved in `work/sf6df01/parsed/accounts_summary.json`.

There are also multiple `4616` time-change events triggered by `C:\Windows\System32\VBoxService.exe`, consistent with VirtualBox guest time adjustments. Example: Security record `456` changes system time to `2015-09-02 05:58:47 UTC`; earlier similar events occur on 2015-08-23. The timeline seat should continue treating source-local times carefully, but the account-creation ordering inside SAM remains internally consistent.

## Bottom line for the report

- **How many users were added?** Two: `user1` and `hacker`.
- **How were they added?** Most likely through an active local `Administrator` session using **Computer Management / Local Users and Groups**, then both were added to **Remote Desktop Users** for future access. This is supported by the `CompMgmtLauncher.exe` UserAssist hit at `2015-09-02 09:01:02 UTC`, followed by SAM account-creation timestamps at `09:05`, then built-in alias membership timestamps at `09:18-09:19`.
- **Were they used successfully?** Not in the retained Security log; there are no successful `user1`/`hacker` logons or `Users\user1` / `Users\hacker` profile directories in the file list.
