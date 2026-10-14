---
id: persistence/quieter-routes
title: Shell, login and other quieter persistence routes
when: Sweeping startup files, PAM, preload, SUID files, modules and boot artefacts.
needs: []
tools: []
requires_host: []
---

Use only if the sweep reaches shell or login scripts or the routes below. Not for units (`persistence/mechanisms`) or cron and timers (`persistence/cron-timers`).

**Shell and login scripts, and the quieter routes.** Read startup files by the shell and the login or interactive mode that applies (`/etc/profile`, `/etc/profile.d/*`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.zshrc`); the file's modification time does not date one line in it. Then SSH authorization and forced `command=` options, PAM configuration and module files, `/etc/ld.so.preload` and loader configuration, file capabilities and SUID or SGID files, module-loading configuration and the modules it names, initramfs and boot artefacts, udev rules, `/etc/rc.local`, container restart policies and application startup hooks. For SUID and SGID, take modes from the image's file listing, or search an extracted tree by naming its root (never `/`, which in a worker is the worker's own filesystem); modes in an extracted tree are only as good as the extraction. Offline there is no `crontab -l`: read the spool file itself.

Shows: a configured route that could start something. Does not show: that it started, when it was added, or by whom. Record: the file, line or mode, the shell and mode that applies, how the mode was read.

Sensitive output: startup files and hooks can hold credentials; cite file and line, never the value.
