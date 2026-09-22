# Memory forensics notes (s2cb902 / Hex)

## Scope
`inputs/memdump.mem` memory triage for report sections on memory artifacts, shellcode, and timeline support.

## Evidence summary

### 1) OS / image context
Command:
```bash
vol -f inputs/memdump.mem windows.info
```
Key output:
- `NtProductType: NtProductServer`
- `NTBuildLab: 6001.18000.x86fre.longhorn_rtm.0`
- `CSDVersion: 1`
- `Is64Bit: False`
- `SystemTime: 2015-09-03 10:04:05+00:00`
- `NtSystemRoot: C:\Windows`

Interpretation: the memory image is from **Windows Server 2008 SP1 x86**. Capture/live time was **2015-09-03 10:04:05 UTC**.

### 2) Active processes at capture time
Command:
```bash
vol -f inputs/memdump.mem windows.pslist
```
Notable processes:
- `2768  xampp-control.exe` created `2015-08-23 10:32:17 UTC`
- `2796  httpd.exe` created `2015-08-23 10:32:21 UTC`
- `2880  httpd.exe` created `2015-08-23 10:32:26 UTC`
- `2804  mysqld.exe` created `2015-08-23 10:32:23 UTC`
- `2856  FileZillaServer.exe` created `2015-08-23 10:32:25 UTC`
- `612   cmd.exe` created `2015-08-23 10:30:44 UTC`
- `1972  cmd.exe` created `2015-09-02 09:28:30 UTC`
- `2120  FTK Imager.exe` created `2015-09-03 10:03:37 UTC`

Interpretation: the host was actively running an internet-facing XAMPP stack (Apache + PHP + MySQL) plus FileZilla FTP server, and two separate `cmd.exe` processes existed in the Administrator session.

### 3) Network exposure from memory
Command:
```bash
vol -f inputs/memdump.mem windows.netscan
```
Key listeners / connections:
- `httpd.exe` PID 2796 listening on `0.0.0.0:80` and `0.0.0.0:443`
- `FileZillaServer` PID 2856 listening on `0.0.0.0:21`
- `mysqld.exe` PID 2804 listening on `0.0.0.0:3306`
- host IP observed as `192.168.56.101`
- `svchost.exe` PID 1108 had `192.168.56.101:51157 -> 192.168.56.1:5357 ESTABLISHED`

Interpretation: web, FTP, and MySQL services were live in memory at capture time.

### 4) Apache/PHP/XAMPP modules loaded in memory
Commands:
```bash
vol -f inputs/memdump.mem windows.dlllist --pid 2796
vol -f inputs/memdump.mem windows.dlllist --pid 2880
vol -f inputs/memdump.mem windows.dlllist --pid 2768
```
Key module evidence from `httpd.exe`:
- `C:\xampp\apache\bin\httpd.exe`
- `C:\xampp\php\php5ts.dll`
- `C:\xampp\php\php5apache2_4.dll`
- `C:\xampp\php\ext\php_mysql.dll`
- `C:\xampp\php\ext\php_mysqli.dll`
- `C:\xampp\php\ext\php_pdo_mysql.dll`
- `C:\xampp\php\ext\php_curl.dll`
- `C:\xampp\php\ext\php_sockets.dll`
- Apache modules including `mod_cgi.so`, `mod_dav.so`, `mod_isapi.so`, `mod_proxy.so`, `mod_rewrite.so`, `mod_ssl.so`

Interpretation: the memory image confirms a fairly broad and potentially risky web stack was loaded, including PHP, CGI, DAV, proxy, SSL, sockets, and curl support.

### 5) Open files and in-memory filesystem artifacts tied to XAMPP
Commands:
```bash
vol -f inputs/memdump.mem windows.handles --pid 2796
vol -f inputs/memdump.mem windows.handles --pid 2804
vol -f inputs/memdump.mem windows.filescan | egrep 'xampp\\(htdocs|apache|php|tmp|mysql)|phpmyadmin'
```
Key evidence:
- `httpd.exe` had open handles to:
  - `\Device\HarddiskVolume1\xampp\apache\logs\access.log`
  - `\Device\HarddiskVolume1\xampp\apache\logs\error.log`
  - `\Device\HarddiskVolume1\xampp\apache\logs\ssl_request.log`
- `mysqld.exe` had open handles to:
  - `\Device\HarddiskVolume1\xampp\mysql\data\mysql\user.MYI`
  - `\Device\HarddiskVolume1\xampp\mysql\data\mysql_error.log`
- `filescan` exposed numerous XAMPP tmp session files and phpMyAdmin artifacts such as:
  - `\xampp\tmp\sess_*`
  - `\xampp\mysql\data\phpmyadmin\pma_users.ibd`
  - `\xampp\mysql\data\phpmyadmin\pma_history.frm`
  - `\xampp\mysql\data\phpmyadmin\pma_tracking.MYD`
  - `\xampp\mysql\data\phpmyadmin\pma_savedsearches.ibd`

Interpretation: phpMyAdmin and PHP session activity were present in memory, which strongly supports a web-application / web-admin attack surface.

### 6) Direct attacker/webshell traces preserved in Apache memory
Commands:
```bash
vol -f inputs/memdump.mem windows.vadregexscan --pattern 'phpshell2\.php|phpshell\.php\?cmd=dir|sqlmap/1\.0-dev-nongit-20150902|tmpudvfh\.php|tmpukudk\.php|tmpbrjvl\.php|sqlmap file uploader|192\.168\.56\.102|4545|fsockopen|proc_open|shell_exec'
python3 <raw-search snippets against inputs/memdump.mem>
```
Key evidence from Apache/PHP and MySQL memory:
- `phpshell2.php` strings present in `httpd.exe` PID `2796` and `2880`
- `phpshell.php?cmd=dir` present in `httpd.exe` PID `2880`
- attacker user-agent `sqlmap/1.0-dev-nongit-20150902 (http://sqlmap.org)` present in `httpd.exe` PID `2880`
- sqlmap temporary backdoor names preserved in memory:
  - `tmpukudk.php` in `httpd.exe` PID `2880` and `mysqld.exe` PID `2804`
  - `tmpudvfh.php` in `httpd.exe` PID `2880` and `mysqld.exe` PID `2804`
  - `tmpbrjvl.php` in `httpd.exe` PID `2880`
  - literal string `sqlmap file uploader` in `mysqld.exe` PID `2804`
- attacker IP `192.168.56.102` present repeatedly in `httpd.exe` PID `2796` and `2880`
- callback port `4545` present in `httpd.exe` PID `2796` and `2880`
- PHP execution / reverse-shell function names present in Apache memory:
  - `shell_exec`
  - `proc_open`
  - `fsockopen`

Representative raw-memory excerpts:
- `GET /dvwa/hackable/uploads/phpshell.php?cmd=dir HTTP/1.1`
- `Host: 192.168.56.101`
- `User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:38.0) Gecko/20100101 Firefox/38.0 Iceweasel/38.2.0`
- `/dvwa/hackable/uploads/phpshell2.php`
- `HTTP/1.1 200 OK`
- `Server: Apache/2.4.16 (Win32) OpenSSL/1.0.1p PHP/5.6.11`
- `192.168.56.102 - - [02/Sep/2015:04:24:31 -0700] "GET /dvwa/vulnerabilities/sqli/?id=2%27 ...` with sqlmap user-agent
- deleted/temporary sqlmap backdoor names retained in memory: `tmpukudk.php`, `tmpudvfh.php`, `tmpbrjvl.php`
- literal uploader marker retained in memory: `sqlmap file uploader`

Interpretation: memory directly preserves attacker HTTP activity against DVWA, the sqlmap staging/backdoor phase, and the later uploaded webshell paths. This ties Apache/PHP (and even MySQL process memory) to attacker host `192.168.56.102`, temporary sqlmap PHP backdoors, and the later reverse-shell callback on port `4545`.

### 7) Command shells in memory
Commands:
```bash
vol -f inputs/memdump.mem windows.cmdline
vol -f inputs/memdump.mem windows.handles --pid 612
vol -f inputs/memdump.mem windows.handles --pid 1972
```
Key evidence:
- Both command shells were `C:\Windows\System32\cmd.exe`
- Both had current-directory handles to `\Device\HarddiskVolume1\Users\Administrator`

Interpretation: memory confirms at least two `cmd.exe` instances under the Administrator context, useful for timeline/supporting attacker activity, though command history was not recoverable with `windows.cmdscan`/`windows.consoles` on this image.

### 8) Shellcode / injection assessment
Commands:
```bash
vol -f inputs/memdump.mem windows.malfind
vol -f inputs/memdump.mem windows.suspicious_threads
vol -f inputs/memdump.mem windows.threads
vol -f inputs/memdump.mem windows.vadinfo --pid 1204 --address 0x1140000 --dump
vol -f inputs/memdump.mem windows.vadregexscan --pid 2796 2880 --pattern '192\.168\.56\.102|4545|fsockopen|proc_open|shell_exec|phpshell2\.php'
```
Observations:
- `windows.suspicious_threads` flagged `svchost.exe` PID `1204` with start addresses `0x129bb9e` and `0x129b2aa` in a non-file-backed VAD starting at `0x1140000`.
- Dumped VAD file: `work/extracted/memory/pid1204/pid.1204.vad.0x1140000-0x1340fff.dmp`
- That dumped region was effectively empty / zeroed when inspected locally.
- `windows.threads` output did **not** clearly corroborate those suspicious start addresses under PID 1204; those exact addresses also appeared under `VBoxTray.exe` PID 1816.
- `windows.malfind` showed only weak/non-conclusive RWX hits (explorer / xampp-control pages) and no recovered PE implant.
- By contrast, Apache/PHP memory contains direct strings for `phpshell2.php`, attacker IP `192.168.56.102`, callback port `4545`, PHP reverse-shell primitives `fsockopen`, `proc_open`, and `shell_exec`, plus sqlmap staging artifacts `tmpukudk.php`, `tmpudvfh.php`, `tmpbrjvl.php`, and `sqlmap file uploader`.

Assessment for report wording:
- The most defensible memory-forensics answer to Q5 is **not a native Windows shellcode family**, but rather a **PHP reverse-shell webshell payload** operating through Apache/PHP.
- Memory preserves the uploaded path `phpshell2.php`, the attacker host `192.168.56.102`, and the callback port `4545`; that matches the disk finding that `phpshell2.php` was a reverse shell.
- Memory also preserves active command-execution use of `phpshell.php?cmd=dir`, sqlmap traffic against DVWA, and the transient sqlmap PHP backdoor names, which supports the broader attack chain: SQLi/web-app abuse -> `INTO OUTFILE` / temporary PHP backdoors -> command-execution webshells -> reverse shell.
- If the final report must use the word `shellcode`, phrase it carefully: **memory did not preserve a recoverable native shellcode blob, but it did preserve a PHP reverse-shell payload/backdoor (`phpshell2.php`) that connected back to 192.168.56.102:4545 and used `fsockopen` / `proc_open` / `shell_exec`.**

## Most reusable citations for the main report
- `inputs/memdump.mem` with `vol -f inputs/memdump.mem windows.info`
- `inputs/memdump.mem` with `vol -f inputs/memdump.mem windows.pslist`
- `inputs/memdump.mem` with `vol -f inputs/memdump.mem windows.netscan`
- `inputs/memdump.mem` with `vol -f inputs/memdump.mem windows.dlllist --pid 2796`
- `inputs/memdump.mem` with `vol -f inputs/memdump.mem windows.handles --pid 2796`
- `inputs/memdump.mem` with `vol -f inputs/memdump.mem windows.handles --pid 2804`
- `inputs/memdump.mem` with `vol -f inputs/memdump.mem windows.filescan | egrep 'xampp\\(htdocs|apache|php|tmp|mysql)|phpmyadmin'`
- `inputs/memdump.mem` with `vol -f inputs/memdump.mem windows.vadregexscan --pattern 'phpshell2\.php|phpshell\.php\?cmd=dir|sqlmap/1\.0-dev-nongit-20150902|tmpudvfh\.php|tmpukudk\.php|tmpbrjvl\.php|sqlmap file uploader|192\.168\.56\.102|4545|fsockopen|proc_open|shell_exec'`
- `work/extracted/memory/pid1204/pid.1204.vad.0x1140000-0x1340fff.dmp` from `windows.vadinfo --dump`
