# Forensic Report

## 1. What type of attack occurred?

The host was compromised through a web application attack against DVWA on XAMPP. The evidence points to:

- **SQL injection / automated exploitation** against DVWA, with `sqlmap` activity visible in the Apache logs.
- **Web-shell upload and command execution** afterward, using attacker-dropped PHP shells and shell archives.
- **Post-exploitation persistence**, including the creation of new local accounts on the Windows host.

In short: this was a **web exploitation -> web shell -> local persistence** intrusion chain.

## 2. Which user accounts were created, and how?

Two non-default local accounts were added during the compromise:

- `user1` — RID `1005`
- `hacker` — RID `1006`

These accounts were created on the compromised host during the attacker activity window, after web access had already been obtained. The exact command line was not recovered from disk, but the surrounding evidence strongly indicates they were created **locally via the attacker’s shell access** rather than through normal administrative setup.

## 3. What artifacts were left behind by the attacker?

Attacker-created or attacker-used artifacts on disk include:

- `xampp/htdocs/DVWA/c99.php`
- `xampp/htdocs/DVWA/webshell.zip`
- `xampp/htdocs/DVWA/webshells/`
- `xampp/htdocs/DVWA/webshells.zip`
- `xampp/htdocs/DVWA/hackable/uploads/phpshell.php`
- `xampp/htdocs/DVWA/hackable/uploads/phpshell2.php`
- `xampp/htdocs/DVWA/hackable/uploads/abc/`
- `Users/Administrator/data.txt` with c99 shell source snippets

These artifacts show both the **payloads used to maintain access** and the **left-behind staging material**.

## 4. What software was installed on the host, and was it malicious?

The installed software inventory included:

- **XAMPP**
- **Microsoft Visual C++ Redistributable**
- **VirtualBox Guest Additions**

These appear to be **legitimate pre-existing software**, not attacker malware. XAMPP is part of the intended web-server stack, and the VC++ / Guest Additions components are normal supporting software. I did not find evidence that these were malicious implants.

## 5. What shellcode was used?

The memory evidence identifies **staged Meterpreter shellcode**. The key indicators were the strings and execution traces:

- `Evaling main meterpreter stage`
- `StreamInjectStagedData`

This is consistent with a **Meterpreter staged payload**, not a standalone custom shellcode blob.

## 6. What did I use to reach these conclusions?

My disk triage focused on:

- Apache access logs
- NTFS file/directory inventory
- SAM/registry account artifacts
- attacker-created files under DVWA and uploads
- file timestamps and creation records

The memory-forensics findings from the other slice confirmed the shellcode type and supported the account-creation timeline.

## 7. Evidence summary

- Web exploitation was visible in the Apache log and matched the DVWA/XAMPP web stack.
- Attacker shell artifacts were left in DVWA web paths and uploads.
- Two new local accounts were added during the compromise.
- Installed system software was consistent with legitimate host setup.
- The shellcode was staged Meterpreter.

## 8. Bottom line

The compromise was a **web-app intrusion against DVWA/XAMPP**, followed by **web shell use, local account creation, and Meterpreter-based memory injection**. The attacker left behind multiple PHP shells and shell archives, plus the local accounts `user1` and `hacker`.
