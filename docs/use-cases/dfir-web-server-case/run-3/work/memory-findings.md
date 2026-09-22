# Memory forensics findings (`sf4b202`)

## Scope and sources

Primary source: `inputs/memdump.mem` (SHA-256 short from `inputs`: `ce6af78989ff`).

Read-only catalog used first:
- `catalog/memdump.mem/windows.info.txt`
- `catalog/memdump.mem/pslist.txt`
- `catalog/memdump.mem/psscan.txt`
- `catalog/memdump.mem/cmdline.txt`
- `catalog/memdump.mem/netscan.txt`
- `catalog/memdump.mem/malfind.txt`
- `catalog/memdump.mem/dlllist.txt`

Follow-up commands run by `sf4b202`:
- `vol -q -f inputs/memdump.mem windows.pstree`
- `vol -q -f inputs/memdump.mem windows.threads > work/extracted/memory/threads.txt`
- `vol -q -f inputs/memdump.mem windows.getsids --pid 816 612 1972 2796 2880 2768 2856 2804 2120`
- `vol -q -f inputs/memdump.mem windows.envars --pid 2796 2880 2804 2856 2768 816 2120`
- `vol -q -f inputs/memdump.mem windows.handles --pid 2796 2880 612 1972 2768 2856`
- `vol -q -f inputs/memdump.mem -o work/extracted/memory/malfind windows.malfind --pid 816 1024 1108 2120 2768 --dump`

## System and capture context

From `catalog/memdump.mem/windows.info.txt`:
- OS: 32-bit Windows Server / Vista family (`NTBuildLab 6001.18000`, `Is64Bit False`, `NtProductType NtProductServer`)
- Host time at capture: `2015-09-03 10:04:05+00:00`
- System root: `C:\Windows`

From `catalog/memdump.mem/pslist.txt` and `cmdline.txt`:
- `FTK Imager.exe` (PID 2120) started at `2015-09-03 10:03:37 UTC` from `\\Vboxsvr\101\FTK-Imager\FTK Imager.exe`, consistent with the responder collecting evidence immediately before the RAM image was acquired.

## User session state visible in memory

From `catalog/memdump.mem/pslist.txt`, `cmdline.txt`, `windows.getsids`, and `windows.envars`:
- `explorer.exe` (PID 816) was running as `Administrator` in the interactive console session.
- Two `cmd.exe` instances were present under `explorer.exe`:
  - PID 612 created `2015-08-23 10:30:44 UTC`
  - PID 1972 created `2015-09-02 09:28:30 UTC`
- `windows.getsids` shows these processes with SID `S-1-5-21-3848053756-3249532031-1848221756-500` (`Administrator`) and `Interactive`/`High Mandatory Level`.

This confirms the compromised machine had an active Administrator desktop session, not just background services.

## XAMPP / web stack visible in memory

From `catalog/memdump.mem/pslist.txt` and `cmdline.txt`:
- `xampp-control.exe` (PID 2768) launched at `2015-08-23 10:32:17 UTC`
- `httpd.exe` (PID 2796) launched at `2015-08-23 10:32:21 UTC`
- child `httpd.exe` (PID 2880) launched at `2015-08-23 10:32:26 UTC`
- `mysqld.exe` (PID 2804) launched at `2015-08-23 10:32:23 UTC`
- `FileZillaServer.exe` (PID 2856) launched at `2015-08-23 10:32:25 UTC`

From `catalog/memdump.mem/netscan.txt`:
- PID 2796 `httpd.exe` listened on `0.0.0.0:80`, `:::80`, `0.0.0.0:443`, and `:::443`
- PID 2804 `mysqld.exe` listened on `0.0.0.0:3306` and `:::3306`
- PID 2856 `FileZillaServer.exe` listened on `0.0.0.0:21`, `:::21`, and localhost admin port `127.0.0.1:14147` / `::1:14147`

From `windows.getsids` and `windows.envars`:
- `xampp-control.exe`, both `httpd.exe` processes, `mysqld.exe`, and `FileZillaServer.exe` all ran as `Administrator` in the interactive console session.

This is important for provenance: the web stack was started from the logged-in Administrator desktop, not isolated service accounts.

## Additional memory-derived artifacts

From `windows.handles`:
- `httpd.exe` had open handles to:
  - `\Device\HarddiskVolume1\xampp\apache\logs\access.log`
  - `\Device\HarddiskVolume1\xampp\apache\logs\error.log`
  - `\Device\HarddiskVolume1\xampp\apache\logs\ssl_request.log`
- `cmd.exe` instances had open handles rooted in `\Device\HarddiskVolume1\Users\Administrator`

These open handles corroborate the disk/log review and show the Apache log files were active at capture.

## Network state at capture

From `catalog/memdump.mem/netscan.txt`:
- No obviously active reverse-shell or remote C2 socket was present at the moment of capture.
- The only non-listening TCP entry in the catalog is `svchost.exe` PID 1108 with `192.168.56.101:51157 -> 192.168.56.1:5357 ESTABLISHED`, which is consistent with local Windows service discovery / WSD behavior rather than attacker-controlled C2.

This does **not** prove there was no earlier remote access; it only means the memory image does not show an obvious live external shell session at acquisition time.

## Malfind / shellcode analysis

### What `malfind` found

`catalog/memdump.mem/malfind.txt` flagged the following private RWX VADs:
- `explorer.exe` PID 816 at `0x9d0000-0x9d0fff`
- `explorer.exe` PID 816 at `0x1f10000-0x1f11fff`
- `svchost.exe` PID 1024 at `0xe60000-0xe61fff`
- `svchost.exe` PID 1108 at `0x6c0000-0x6c1fff`
- `xampp-control.exe` PID 2768 at `0x280000-0x280fff`
- `FTK Imager.exe` PID 2120 at `0x4f40000-0x4f41fff`

Extracted dumps:
- `work/extracted/memory/malfind/pid.816.vad.0x9d0000-0x9d0fff.dmp`
- `work/extracted/memory/malfind/pid.816.vad.0x1f10000-0x1f11fff.dmp`
- `work/extracted/memory/malfind/pid.1024.vad.0xe60000-0xe61fff.dmp`
- `work/extracted/memory/malfind/pid.1108.vad.0x6c0000-0x6c1fff.dmp`
- `work/extracted/memory/malfind/pid.2768.vad.0x280000-0x280fff.dmp`
- `work/extracted/memory/malfind/pid.2120.vad.0x4f40000-0x4f41fff.dmp`

SHA-256:
- `17db0883f0c0ba937540e0f93ee15117ee327a9459203eea9b9e999d6a288049`  `pid.1024.vad.0xe60000-0xe61fff.dmp`
- `6608784055bfb26ced46ff06f955bf1d13948af9f6e8d4e742e612fc53fe78ed`  `pid.1108.vad.0x6c0000-0x6c1fff.dmp`
- `e3f231f2b3d995a190707af3df58a2e6bf37f6e6743838d78dce1e79084e2367`  `pid.2120.vad.0x4f40000-0x4f41fff.dmp`
- `407213d0c51843e14c08966c07ccde1f18cbbc0466a2444d2c7db66dcdbb11bd`  `pid.2768.vad.0x280000-0x280fff.dmp`
- `00de6b2a1bc6c33baad34ecd2d5483bb3efa724bb3da26c7988d69842cb588e4`  `pid.816.vad.0x1f10000-0x1f11fff.dmp`
- `327a442a1d311f1dbb93eac838d288f5b995504a478573d4ad01aa6bc9df925d`  `pid.816.vad.0x9d0000-0x9d0fff.dmp`

### What the dumped bytes look like

The 8 KB RWX dumps for `explorer.exe`, `svchost.exe` (two PIDs), and `FTK Imager.exe` all begin with the same byte pattern:

`b0 00 eb 70 b0 01 eb 6c b0 02 eb 68 ... 33 c9 8a c8 81 c1 80 00 00 00 ff 25`

A quick capstone disassembly shows a repeated jump-table-like thunk pattern such as:
- `mov al, 0x00 ; jmp 0x74`
- `mov al, 0x01 ; jmp 0x74`
- ...
- shared tail at `0x74`: `xor ecx, ecx ; mov cl, al ; add ecx, 0x80 ; jmp dword ptr [0x77359d80]`

The 4 KB `xampp-control.exe` region also looks table-like rather than like a standalone shell payload. The 4 KB `explorer.exe` region at `0x9d0000` appears to be pointer/data content, not a decoder or stage body.

### Thread correlation

`windows.threads` output was saved to `work/extracted/memory/threads.txt` and checked for thread start addresses landing inside these flagged VADs. No thread `StartAddress` or `Win32StartAddress` fell inside:
- `0x9d0000-0x9d0fff`
- `0x1f10000-0x1f11fff`
- `0xe60000-0xe61fff`
- `0x6c0000-0x6c1fff`
- `0x280000-0x280fff`
- `0x4f40000-0x4f41fff`

### Assessment for question 5

**Current assessment:** memory does **not** provide a defensible positive identification of a live attacker shellcode family.

What I can support:
- `malfind` found RWX private VADs.
- The main flagged blobs are highly repetitive and nearly identical across unrelated processes (`explorer.exe`, `svchost.exe`, and even responder-launched `FTK Imager.exe`).
- No thread starts inside those VADs.
- The content looks more like shared thunk / RPC / GUI glue or another false-positive style pattern than a unique attacker stage.

So for the report, the safest wording is:
- memory triage found **suspicious RWX regions**, but
- the recovered regions do **not** support a high-confidence family ID such as Meterpreter/reverse TCP/bind shell from memory alone.

If another seat finds a dropped payload on disk that matches these memory artifacts, we can revisit and tighten question 5.

### Cross-seat corroboration added after disk/web review

`work/leftovers.md` and `work/timeline.md` add an important clarification for question 5: the attacker uploaded `phpshell2.php` (inode `62337-128-4`, `2015-09-03T07:31:30Z`), whose source connects to `192.168.56.102:4545` and `eval()`s a second-stage payload received over the socket. Per the leftovers/timeline seats, this is structurally consistent with a **PHP Meterpreter reverse TCP stager** rather than native Windows shellcode injected into a process.

That cross-seat result fits the memory evidence well:
- the clearly malicious execution path on this host is web-shell / PHP stager activity in the XAMPP/DVWA stack;
- the RWX VAD hits from `malfind` still do **not** show an executing thread inside them;
- therefore the safest report wording is that memory did **not** confirm native injected shellcode, while disk/web evidence supports a **PHP reverse-shell / Meterpreter-style stager** used through the compromised web application.

## High-confidence takeaways for the report

1. The host was alive with an interactive `Administrator` session at capture.
2. XAMPP, Apache, MySQL, and FileZilla Server were running in that Administrator session.
3. Apache was actively holding its log files open in memory.
4. No obvious active reverse shell / C2 socket is visible at capture time.
5. `malfind` artifacts exist, but they do not currently justify a strong claim that a specific shellcode family was still resident and active in RAM.
