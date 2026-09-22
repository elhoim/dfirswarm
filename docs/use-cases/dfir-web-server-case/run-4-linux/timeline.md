| Date (UTC) | Event | Evidence |
| --- | --- | --- |
| 2015-08-23T21:43:54Z | Microsoft Visual C++ 2008 Redistributable x86 was installed. | `work/extracted/s309602/Windows__System32__config__SOFTWARE` (InstalledProgramsSoftwarePlugin, DisplayName/timestamp) |
| 2015-08-23T21:44:08Z | XAMPP 5.6.11-1 was installed. | `work/extracted/s309602/Windows__System32__config__SOFTWARE` (InstalledProgramsSoftwarePlugin, DisplayName/timestamp) |
| 2015-08-24T07:14:15Z | Oracle VM VirtualBox Guest Additions 4.3.30 were installed. | `work/extracted/s309602/Windows__System32__config__SOFTWARE` (InstalledProgramsSoftwarePlugin) |
| 2015-09-02T07:11:12Z | The attacker first hit `/dvwa/` and `/dvwa/login.php` from 192.168.56.102. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T07:11:12Z | The attacker loaded DVWA login assets (`login.css`, `login_logo.png`). | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T07:15:12Z | The attacker revisited `/dvwa/` and `/dvwa/login.php`. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T07:33:04Z | Another DVWA session began with a fresh `/dvwa/` request. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T07:33:15Z | The attacker requested `/dvwa/login.php` again. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:34:27Z | The attacker loaded the login assets again using an IE6 user agent. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:35:53Z | The attacker browsed the DVWA index and directory listings. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:35:56Z | The attacker enumerated DVWA subdirectories such as `css`, `images`, `includes`, and `js`. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:35:57Z | The attacker enumerated `includes/DBMS` and fetched `dvwaPage.inc.php` and `dvwaPhpIds.inc.php`. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:35:58Z | The attacker fetched the DBMS backend files `PGSQL.php`, `MySQL.php`, and `DBMS.php`. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:43:29Z | The attacker logged in and explored DVWA modules including brute, exec, csrf, captcha, fi, sqli, upload, xss, security, setup, phpinfo, and about. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:43:30Z | The attacker navigated the vulnerable module index and repeated the module scan. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:43:30Z | The attacker attempted the brute-force module with `username=admin&password=password`. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:43:31Z | The attacker probed the IDS log and XSS-related pages. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:43:46Z | The attacker tested the CSRF password-change vector. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:43:46Z | The attacker posted to the CAPTCHA page. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:44:35Z | The attacker repeated brute-force and CSRF payloads, then hit `ids_log.php?clear_log=Clear+Log`. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:47:09Z | The attacker logged back into DVWA with a Firefox-based user agent. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:47:10Z | The attacker loaded the DVWA index and main assets. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:47:28Z | The attacker visited `security.php` again. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:50:03Z | The attacker opened the command execution vulnerability page. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:50:33Z | The attacker submitted command-execution payloads to `/dvwa/vulnerabilities/exec/`. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:51:14Z | The attacker continued command-execution testing on the exec module. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T08:52:09Z | The attacker changed DVWA security settings. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T11:23:45Z | sqlmap launched a UNION-based SQL injection against `mysql.user` through the DVWA SQLi module. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T11:25:53Z | sqlmap tested command execution through `tmpbiwuc.php?cmd=echo command execution test`. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T11:26:04Z | sqlmap ran `dir` through the temporary web shell `tmpbiwuc.php`. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-02T11:26:23Z | sqlmap deleted its temporary web shells `tmpukudk.php` and `tmpbiwuc.php`. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-03T06:08:35Z | The attacker opened DVWA's upload vulnerability page. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-03T06:10:15Z | The attacker uploaded `phpshell.php` via the DVWA upload form. | `work/extracted/s309602/xampp__apache__logs__access.log` and `work/extracted/s309602/xampp__htdocs__DVWA__hackable__uploads__phpshell.php` |
| 2015-09-03T06:15:58Z | The attacker fetched `phpshell.php` from `/dvwa/hackable/uploads/`. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-03T06:16:13Z | The attacker used `phpshell.php?cmd=dir` to execute commands remotely. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-03T06:17:49Z | The attacker used `phpshell.php?cmd=dir C:\` to enumerate the filesystem. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-03T06:17:58Z | The attacker used `phpshell.php?cmd=mkdir abc` to create a directory. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-03T06:18:02Z | The attacker repeated `phpshell.php?cmd=dir` after creating the directory. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-03T06:18:58Z | The attacker revisited `phpshell.php`. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-03T06:19:32Z | The attacker opened `c99.php` in DVWA. | `work/extracted/s309602/xampp__apache__logs__access.log` and `work/extracted/s309602/xampp__htdocs__DVWA__c99.php` |
| 2015-09-03T06:20:59Z | The attacker loaded the c99 shell interface assets and browsed the shell UI. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-03T06:21:28Z | The attacker posted to `c99.php?act=cmd` to execute commands. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-03T06:21:37Z | The attacker posted another command to `c99.php?act=cmd`. | `work/extracted/s309602/xampp__apache__logs__access.log` |
| 2015-09-03T06:31:54Z | The attacker fetched `phpshell2.php`, a reverse-shell payload. | `work/extracted/s309602/xampp__apache__logs__access.log` and `work/extracted/s309602/xampp__htdocs__DVWA__hackable__uploads__phpshell2.php` |
| 2015-09-02T09:05:06Z | The local account `user1` (RID 1005) was created in SAM. | `work/extracted/s309602/Windows__System32__config__SAM` |
| 2015-09-02T09:05:25Z | The local account `hacker` (RID 1006) was created in SAM. | `work/extracted/s309602/Windows__System32__config__SAM` |
| 2015-09-02T09:32:47Z | `Users/Administrator/data.txt` was created/modified and left behind as attacker material. | `work/extracted/s309602/Users/Administrator/data.txt` |
| 2015-09-03T07:10:15Z | `phpshell.php` exists on disk in DVWA uploads. | `work/extracted/s309602/xampp__htdocs__DVWA__hackable__uploads__phpshell.php` |
| 2015-09-03T07:14:48Z | `webshells.zip` was created in the DVWA web root. | `work/extracted/s309602/xampp__htdocs__DVWA__webshells.zip` |
| 2015-09-03T07:14:51Z | The `webshells` directory was created in the DVWA web root. | `work/extracted/s309602/xampp__htdocs__DVWA` |
| 2015-09-03T07:17:58Z | The `abc` directory was created under `hackable/uploads`. | `work/extracted/s309602/xampp__htdocs__DVWA__hackable__uploads__abc` and access log `mkdir abc` |
| 2015-09-03T07:20:45Z | `c99.php` was modified in the DVWA web root. | `work/extracted/s309602/xampp__htdocs__DVWA__c99.php` |
| 2015-09-03T07:31:30Z | `phpshell2.php` was created in `hackable/uploads`. | `work/extracted/s309602/xampp__htdocs__DVWA__hackable__uploads__phpshell2.php` |
| 2015-09-12T18:18:24Z | The event logs were updated after the incident window. | `work/extracted/s309602/Windows__System32__winevt__Logs__*.evtx` |
| 2015-09-12T18:19:19Z | The SAM hive and SAM transaction log were updated. | `work/extracted/s309602/Windows__System32__config__SAM` and `SAM.LOG1` |
| 2015-09-12T18:20:03Z | The SECURITY hive and SECURITY transaction log were updated. | `work/extracted/s309602/Windows__System32__config__SECURITY` and `SECURITY.LOG1` |
| 2015-09-12T18:24:08Z | The SYSTEM hive and SYSTEM transaction log were updated. | `work/extracted/s309602/Windows__System32__config__SYSTEM` and `SYSTEM.LOG1` |
| 2015-09-12T18:24:27Z | The SOFTWARE hive and SOFTWARE transaction log were updated. | `work/extracted/s309602/Windows__System32__config__SOFTWARE` and `SOFTWARE.LOG1` |
