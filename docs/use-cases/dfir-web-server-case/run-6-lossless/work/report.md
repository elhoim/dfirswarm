## 1. What type of attacks has been performed on the box?

The box was attacked through a web application compromise centered on DVWA/XAMPP:

- SQL injection automated with sqlmap against `/dvwa/vulnerabilities/sqli/`.
- Command execution through DVWA's `exec` module.
- File inclusion / traversal through DVWA's `fi` module.
- Web-shell staging and execution through dropped PHP shells in the DVWA tree and `%TEMP%`.
- Upload abuse, including a reverse shell payload.

Evidence:
- `work/extracted/s50bb03/logs/access.log` shows `sqlmap/1.0-dev-nongit-20150902` requests, `INTO OUTFILE`-style temp shell creation, `/dvwa/vulnerabilities/exec/`, `/dvwa/vulnerabilities/fi/`, `/dvwa/vulnerabilities/upload/`, and later `/dvwa/c99.php` / `/dvwa/hackable/uploads/phpshell.php` access.
- `work/extracted/s50bb03/dvwa/xampp_htdocs_DVWA_c99.php` is a PHP command shell (`system($_GET["cmd"])`).
- `work/extracted/s50bb03/dvwa/xampp_htdocs_DVWA_hackable_uploads_phpshell2.php` is a reverse shell to `192.168.56.102:4545`.

## 2. How many users has the attacker(s) added to the box, and how were they added?

I found **two** attacker-added local users in SAM:

- `hacker`
- `user1`

Evidence:
- `work/extracted/s50bb03/hives/SAM` contains both names under `SAM\Domains\Account\Users\Names` and RID subkeys `000003ED` and `000003EE`.
- The `Names` subkeys' last-write timestamps correspond to `2015-09-02T09:05:06Z` (`user1`) and `2015-09-02T09:05:25Z` (`hacker`).
- This lines up with the attacker's active command-execution window in `work/extracted/s50bb03/logs/access.log`.

How they were added: the evidence shows they were added as **local SAM accounts** during the intrusion window. Peer registry analysis linked their creation to Computer Management / Local Users and Groups (`CompMgmtLauncher.exe` in UserAssist), which is consistent with local account creation through the GUI or its underlying management APIs rather than through a software installer.

## 3. What leftovers did the attacker(s) leave behind?

The attacker left multiple web shells, staging files, and other artifacts:

- `work/extracted/s50bb03/dvwa/xampp_htdocs_DVWA_c99.php`
- `work/extracted/s50bb03/dvwa/xampp_htdocs_DVWA_webshell.php`
- `work/extracted/s50bb03/dvwa/xampp_htdocs_DVWA_webshells.zip`
- `work/extracted/s50bb03/dvwa/xampp_htdocs_DVWA_webshells/`
- `work/extracted/s50bb03/dvwa/xampp_htdocs_DVWA_hackable_uploads_phpshell.php`
- `work/extracted/s50bb03/dvwa/xampp_htdocs_DVWA_hackable_uploads_phpshell2.php`
- `work/extracted/s50bb03/dvwa/xampp_htdocs_DVWA_hackable_uploads_abc/` (directory)
- `work/extracted/s50bb03/temp/c99_(2).php`
- `work/extracted/s50bb03/temp/ad_driver.sys`
- `work/extracted/s50bb03/temp/~DF8445.tmp`
- Apache logs under `work/extracted/s50bb03/logs/`
- EVTX logs under `work/extracted/s50bb03/evtx/`

Evidence:
- The extracted PHP files show shell code and reverse-shell behavior.
- `work/extracted/s50bb03/temp/ad_driver.sys` is a PE32 driver with debug symbols and a PDB path.
- `work/extracted/s50bb03/logs/access.log` shows requests to the shells, directory creation (`abc`), and cleanup commands.

## 4. What software has been installed on the box, and were they installed by the attacker(s) or not?

Installed software I could verify:

- **XAMPP 5.6.11-1** — legitimate/vendor-installed, not attacker-installed.
- **Microsoft Visual C++ 2008 Redistributable - x86 9.0.21022** — installed before the attack window.
- **Oracle VM VirtualBox Guest Additions 4.3.30** — also present before the attack window.

Peer registry/UserAssist analysis also indicates the XAMPP installer and XAMPP Control Panel were run by the Administrator profile, which supports the software being a normal preexisting stack rather than attacker malware.

Evidence:
- `work/extracted/s50bb03/hives/SOFTWARE` under `Microsoft\Windows\CurrentVersion\Uninstall` shows the above DisplayName / DisplayVersion entries.
- XAMPP is registered with `Publisher=Bitnami`, `InstallLocation=C:\xampp`, and the install timestamp predates the attacker activity.

## 5. Using memory forensics, can you identify the type of shellcode used?

The memory artifact contains **Meterpreter** strings, so the shellcode is best described as Meterpreter-based; the exact stage appears to be a PHP Meterpreter stage.

Evidence:
- `strings -a inputs/memdump.mem | grep -i -C 2 'Meterpreter'` shows `Evaling main meterpreter stage` and the standard Meterpreter comment about `File.expand_path`.
- This strongly suggests a Meterpreter payload rather than a simple bind shell.

## 6. What is the timeline analysis for all events that happened on the box?

See `work/timeline.md` for the merged table. In short:

1. XAMPP/VirtualBox environment exists before the compromise.
2. The attacker reaches DVWA and toggles security settings.
3. They probe `exec`, `fi`, and `upload` modules.
4. They pivot to `sqlmap` against SQLi.
5. They write temp PHP shells, execute them, and delete them.
6. They stage and execute `c99.php` and the upload web shell.
7. They create two local accounts in SAM during the same window.
8. They leave behind temp files and a driver artifact.

## 7. What is your hypothesis for the case, and what is your approach in solving it?

Hypothesis:
- The machine was a deliberately exposed lab host (XAMPP + DVWA) that an attacker compromised through web-app flaws.
- The attacker used web-shell and command-execution footholds to enumerate the system, dump data, stage shells, and create local accounts.
- The memory side points to Meterpreter tooling, so the intrusion likely moved from web exploitation to a staged post-exploitation payload.

Approach:
- Triage the disk image first to identify filesystem layout, web roots, temp artifacts, and installed software.
- Pull out evidence into `work/extracted/s50bb03/` and inspect it directly.
- Correlate the disk artifacts with Apache logs, registry hives, and event logs.
- Use memory strings / memory-forensics tooling to identify the payload type.

## 8. Is there anything else you would like to add?

A few notes:

- The strongest disk-side evidence is the Apache log chain plus the web shells on disk.
- XAMPP appears to be legitimate preexisting software, not a malicious install.
- The attacker did not fully clean up: the web shells, temp copy of `c99.php`, the driver file, logs, and account traces remain.
- The two added local accounts were `hacker` and `user1`; peer registry evidence ties their creation to Windows Computer Management / Local Users and Groups.

## Bonus: directories and files added by the attacker(s)

Verified attacker-added directories/files include:

- `/xampp/htdocs/DVWA/c99.php` — `work/extracted/s50bb03/dvwa/xampp_htdocs_DVWA_c99.php`
- `/xampp/htdocs/DVWA/webshell.php` — `work/extracted/s50bb03/dvwa/xampp_htdocs_DVWA_webshell.php`
- `/xampp/htdocs/DVWA/webshells.zip` — `work/extracted/s50bb03/dvwa/xampp_htdocs_DVWA_webshells.zip`
- `/xampp/htdocs/DVWA/webshells/` — directory present in NTFS listing and zip extraction context
- `/xampp/htdocs/DVWA/hackable/uploads/phpshell.php` — `work/extracted/s50bb03/dvwa/xampp_htdocs_DVWA_hackable_uploads_phpshell.php`
- `/xampp/htdocs/DVWA/hackable/uploads/phpshell2.php` — `work/extracted/s50bb03/dvwa/xampp_htdocs_DVWA_hackable_uploads_phpshell2.php`
- `/xampp/htdocs/DVWA/hackable/uploads/abc/` — directory created during the attack, visible in the filesystem and Apache log
- `%TEMP%/c99 (2).php` — `work/extracted/s50bb03/temp/c99_(2).php`
- `%TEMP%/ad_driver.sys` — `work/extracted/s50bb03/temp/ad_driver.sys`
- `%TEMP%/~DF8445.tmp` — `work/extracted/s50bb03/temp/~DF8445.tmp`

Proof sources:
- `work/extracted/s50bb03/logs/access.log`
- `work/extracted/s50bb03/dvwa/`
- `work/extracted/s50bb03/temp/`
- NTFS directory listings from `pytsk3` against `inputs/s4a-challenge4`
