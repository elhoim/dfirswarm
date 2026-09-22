# Master timeline

| Time | Event | Evidence |
| --- | --- | --- |
| 2015-08-23 21:41:46 UTC | The XAMPP tree appears on disk, indicating the base web stack was already in place. | `pytsk3` metadata for `/xampp` |
| 2015-08-23 21:41:48 UTC | `passwords.txt` under `/xampp` is created with the default-password guidance that ships with XAMPP. | `pytsk3` metadata for `/xampp/passwords.txt` |
| 2015-08-23 21:44:18 UTC | The `/xampp` directory is modified again shortly after initial creation. | `pytsk3` metadata for `/xampp` |
| 2015-08-23 21:52:15 UTC | The `/xampp/htdocs/DVWA` directory exists on disk. | `pytsk3` metadata for `/xampp/htdocs/DVWA` |
| 2015-08-24 06:59:37 UTC | Administrator password metadata is last set in SAM. | `SAM` hive, RID `000001F4` |
| 2015-08-24 06:52:40 UTC | Guest account metadata is last written in SAM. | `SAM` hive, RID `000001F5` |
| 2015-09-01 23:00:22 -0700 | The local host browses DVWA’s upload page. | `work/extracted/sd8ee03/apache/access.log` line 3300 |
| 2015-09-01 23:03:19 -0700 | The local host browses the XSS lab after visiting the upload page. | `work/extracted/sd8ee03/apache/access.log` line 3301 |
| 2015-09-02 01:35:51 -0700 | A client fetches DVWA’s reset-mysql-password guide. | `work/extracted/sd8ee03/apache/access.log` line 3418 |
| 2015-09-02 01:35:52 -0700 | The same client fetches the PDF guide and its images. | `work/extracted/sd8ee03/apache/access.log` lines 3499, 3503, 3514, 3524, 3586, 3628, 3630-3632, 3717-3721 |
| 2015-09-02 01:43:29 -0700 | The attacker starts probing DVWA’s upload page from 192.168.56.102. | `work/extracted/sd8ee03/apache/access.log` line 3831 |
| 2015-09-02 01:43:30 -0700 | The attacker repeats the upload-page request and starts brute-forcing admin/password. | `work/extracted/sd8ee03/apache/access.log` lines 3832, 3856, 3863-3864 |
| 2015-09-02 01:43:31 -0700 | The attacker inspects the hackable users directory. | `work/extracted/sd8ee03/apache/access.log` lines 3873-3875 |
| 2015-09-02 01:43:46 -0700 | The attacker sends DVWA CSRF password-change requests. | `work/extracted/sd8ee03/apache/access.log` lines 3876-3888 |
| 2015-09-02 02:33:23 -0700 | DVWA file inclusion is used to read `/users/administrator/data.txt`. | `work/extracted/sd8ee03/apache/access.log` line 3943 |
| 2015-09-02 02:34:52 -0700 | DVWA file inclusion is used to read `/xampp/phpmyadmin/config.inc`. | `work/extracted/sd8ee03/apache/access.log` line 3944 |
| 2015-09-02 02:36:48 -0700 | The attacker retries the file-inclusion path against `data.txt`. | `work/extracted/sd8ee03/apache/access.log` line 3955 |
| 2015-09-02 04:23:45 -0700 | sqlmap begins UNION-based SQL injection against DVWA’s SQLi lab, targeting `mysql.user`. | `work/extracted/sd8ee03/apache/access.log` line 7378 |
| 2015-09-02 04:24:30 -0700 | sqlmap continues extracting phpMyAdmin metadata tables. | `work/extracted/sd8ee03/apache/access.log` lines 7384-7391 |
| 2015-09-02 04:24:31 -0700 | sqlmap continues enumerating `phpmyadmin.pma_relation` and related tables. | `work/extracted/sd8ee03/apache/access.log` lines 7394-7403 |
| 2015-09-02 04:24:32 -0700 | sqlmap continues enumeration of `phpmyadmin.pma_navigationhiding` and `phpmyadmin.pma_table_uiprefs`. | `work/extracted/sd8ee03/apache/access.log` lines 7404-7423 |
| 2015-09-02 04:24:32 -0700 | sqlmap starts extracting `phpmyadmin.pma_bookmark`. | `work/extracted/sd8ee03/apache/access.log` lines 7424-7427 |
| 2015-09-02 04:25:52 -0700 | sqlmap writes a PHP payload to `/xampp/htdocs/tmpukudk.php` via `INTO OUTFILE`. | `work/extracted/sd8ee03/apache/access.log` line 7600 |
| 2015-09-02 04:25:53 -0700 | The attacker requests `/tmpukudk.php`, which returns the webshell stub. | `work/extracted/sd8ee03/apache/access.log` lines 7602-7604 |
| 2015-09-02 04:25:53 -0700 | The attacker tests command execution with `/tmpbiwuc.php?cmd=echo command execution test`. | `work/extracted/sd8ee03/apache/access.log` line 7605 |
| 2015-09-02 04:26:04 -0700 | The attacker runs `dir` through the temp webshell. | `work/extracted/sd8ee03/apache/access.log` line 7606 |
| 2015-09-02 04:26:23 -0700 | The attacker cleans up the temporary PHP shells with `del /F /Q`. | `work/extracted/sd8ee03/apache/access.log` lines 7607-7608 |
| 2015-09-02 09:05:06 UTC | The `hacker` local account is added or modified in SAM (RID 1005). | `SAM` hive, RID `000003ED` |
| 2015-09-02 09:05:25 UTC | The `user1` local account is added or modified in SAM (RID 1006). | `SAM` hive, RID `000003EE` |
| 2015-09-02 23:52:24 -0700 | A second SQLi-derived PHP payload is written to `/xampp/htdocs/tmpudvfh.php`. | `work/extracted/sd8ee03/apache/access.log` line 7657 |
| 2015-09-02 23:52:24 -0700 | The attacker requests `/tmpudvfh.php` and receives the shell stub. | `work/extracted/sd8ee03/apache/access.log` lines 7658-7661 |
| 2015-09-02 23:52:24 -0700 | The attacker tests command execution through `/tmpbrjvl.php?cmd=echo command execution test`. | `work/extracted/sd8ee03/apache/access.log` line 7662 |
| 2015-09-02 23:59:38 -0700 | The attacker cleans up the second set of temp PHP shells. | `work/extracted/sd8ee03/apache/access.log` lines 7663-7664 |
| 2015-09-03 00:08:35 -0700 | The attacker revisits DVWA’s upload page. | `work/extracted/sd8ee03/apache/access.log` line 7677 |
| 2015-09-03 00:10:15 -0700 | The attacker submits a DVWA file upload. | `work/extracted/sd8ee03/apache/access.log` line 7678 |
| 2015-09-03 00:15:58 -0700 | `/dvwa/hackable/uploads/phpshell.php` is fetched and used as a webshell. | `work/extracted/sd8ee03/apache/access.log` lines 7681-7687 and file metadata for `/xampp/htdocs/DVWA/hackable/uploads/phpshell.php` |
| 2015-09-03 00:17:58 -0700 | The attacker creates directory `abc` through the uploaded webshell. | `work/extracted/sd8ee03/apache/access.log` line 7685 and file metadata for `/xampp/htdocs/DVWA/hackable/uploads/abc` |
| 2015-09-03 00:19:32 -0700 | The attacker loads `c99.php`, another webshell dropped in the DVWA tree. | `work/extracted/sd8ee03/apache/access.log` line 7688 |
| 2015-09-03 00:20:59 -0700 | `c99.php` loads its UI assets, confirming active use. | `work/extracted/sd8ee03/apache/access.log` lines 7689-7709 |
| 2015-09-03 00:21:28 -0700 | The attacker posts to `c99.php?act=cmd` to run commands. | `work/extracted/sd8ee03/apache/access.log` line 7711 |
| 2015-09-03 00:21:37 -0700 | The attacker issues another `c99` command post. | `work/extracted/sd8ee03/apache/access.log` line 7712 |
| 2015-09-03 00:31:30 -0700 | The attacker uploads another file through DVWA. | `work/extracted/sd8ee03/apache/access.log` line 7715 |
| 2015-09-03 00:31:54 -0700 | `/dvwa/hackable/uploads/phpshell2.php` is fetched; it contains a reverse shell to 192.168.56.102:4545. | `work/extracted/sd8ee03/apache/access.log` line 7716 and file content of `/xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` |
| 2015-09-03 07:10:15 UTC | `phpshell.php` is timestamped on disk, matching the webshell activity. | file metadata for `/xampp/htdocs/DVWA/hackable/uploads/phpshell.php` |
| 2015-09-03 07:14:48 UTC | `webshells.zip` is timestamped on disk. | file metadata for `/xampp/htdocs/DVWA/webshells.zip` |
| 2015-09-03 07:14:51 UTC | The `webshells` directory appears on disk. | file metadata for `/xampp/htdocs/DVWA/webshells` |
| 2015-09-03 07:17:58 UTC | The `abc` directory is timestamped on disk. | file metadata for `/xampp/htdocs/DVWA/hackable/uploads/abc` |
| 2015-09-03 07:20:45 UTC | `c99.php` is timestamped on disk. | file metadata for `/xampp/htdocs/DVWA/c99.php` |
| 2015-09-03 07:31:30 UTC | `phpshell2.php` is timestamped on disk. | file metadata for `/xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` |
