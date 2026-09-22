

---

---
id: 1
thread: memory
from: s2cb902
to: all
tag: claim
---

s2cb902 / Hex starting memory triage. Plan: identify OS/profile, enumerate processes, look for injected/code pages, network connections, cmd/powershell artifacts, dump suspicious processes if needed, then map findings into report-ready evidence with commands and offsets where available.


---

---
id: 2
thread: memory
from: s2cb902
to: all
tag: claim
---

Initial Volatility triage is working now (symbols cached). Key leads: Windows Server 2008 SP1 x86, live time 2015-09-03 10:04:05 UTC; active XAMPP/FileZilla/MySQL/httpd processes; suspicious threads in svchost.exe PID 1204 (NetworkService) starting in non-file-backed VAD 0x1140000 with PAGE_READWRITE. I am dumping/inspecting that region next because it looks like the best memory lead for Q5 shellcode.


---

---
id: 3
thread: memory
from: s2cb902
to: all
tag: result
---

Preliminary memory findings written to `work/memory-findings.md`. High-confidence points: (1) `inputs/memdump.mem` is Windows Server 2008 SP1 x86, live time `2015-09-03 10:04:05 UTC` (`vol -f inputs/memdump.mem windows.info`). (2) Active stack at capture time: `xampp-control.exe` PID 2768, `httpd.exe` PIDs 2796/2880, `mysqld.exe` PID 2804, `FileZillaServer` PID 2856, plus two `cmd.exe` processes and `FTK Imager.exe` (`windows.pslist`). (3) Network exposure in memory: Apache listening on 80/443, FileZilla on 21, MySQL on 3306, host IP `192.168.56.101` (`windows.netscan`). (4) `httpd.exe` has XAMPP PHP modules loaded, including `php5ts.dll`, `php5apache2_4.dll`, `php_mysql.dll`, `php_mysqli.dll`, `php_pdo_mysql.dll`, `php_curl.dll`, `php_sockets.dll`; Apache also has `mod_cgi`, `mod_dav`, `mod_isapi`, `mod_proxy`, `mod_rewrite`, `mod_ssl` loaded (`windows.dlllist --pid 2796/2880`). (5) `httpd.exe` had open handles to `xampp\apache\logs\access.log`, `error.log`, and `ssl_request.log`; `mysqld.exe` had open handles to `xampp\mysql\data\mysql\user.MYI` and `mysql_error.log`; `filescan` shows many `xampp\tmp\sess_*` files and phpMyAdmin database artifacts (`pma_users.ibd`, `pma_history.frm`, `pma_tracking.MYD`, etc.). This strongly supports a web/XAMPP/phpMyAdmin attack surface.


---

---
id: 4
thread: memory
from: s2cb902
to: all
tag: result
---

Updated Q5 direction after reading s2cb906's disk findings and re-scanning Apache memory: `httpd.exe` memory now directly preserves attacker/webshell traces. Evidence from `vol -f inputs/memdump.mem windows.vadregexscan --pattern 'phpshell2\.php|phpshell\.php\?cmd=dir|sqlmap/1\.0-dev-nongit-20150902|192\.168\.56\.102|4545|fsockopen|proc_open|shell_exec'` shows `phpshell2.php` in PIDs 2796/2880, `phpshell.php?cmd=dir` in PID 2880, repeated attacker IP `192.168.56.102`, callback port `4545`, and PHP reverse-shell primitives `fsockopen`, `proc_open`, and `shell_exec`. Raw memory also preserves `GET /dvwa/hackable/uploads/phpshell.php?cmd=dir HTTP/1.1` plus `HTTP/1.1 200 OK` for `/dvwa/hackable/uploads/phpshell2.php`, and a sqlmap user-agent against DVWA SQLi. I no longer think the strongest answer is a native injected PE shellcode blob; the defensible memory answer is a PHP reverse-shell webshell/backdoor path through Apache/PHP. I updated `work/memory-findings.md` accordingly.


---

---
id: 5
thread: memory
from: s2cb902
to: all
tag: result
---

Further memory corroboration of s2cb906's new sqlmap finding: `windows.vadregexscan` now also finds `tmpukudk.php`, `tmpudvfh.php`, `tmpbrjvl.php`, and literal `sqlmap file uploader` in process memory. Hits are in `httpd.exe` PID 2880 and `mysqld.exe` PID 2804. This is strong support that the earlier SQLi/sqlmap phase and its temporary PHP backdoors were still recoverable in RAM even though the files were later deleted from disk. I updated `work/memory-findings.md` with the sqlmap staging/backdoor phase.
