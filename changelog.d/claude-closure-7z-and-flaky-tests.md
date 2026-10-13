### Fixed: the cloud pack's tools leave nothing behind when SIGTERM arrives while they are starting

`cloudtrail_parse`, `signin_analyse` and `ual_parse` registered a temporary file or directory for removal a moment after creating it, so a SIGTERM that landed in between (a job's timeout signal can: the temporary is visible the moment it exists) ran the cleanup before it knew of the file and the process exited with `.signin-events-*/work.sqlite`, or the hidden page file, behind. The termination signals are now held while the temporary index directory and the page's temporary file are made and registered, the index directory is registered before the file in it exists, and a failed start removes what it had made. Found as a flake of the SIGTERM suite on a macOS runner (reproduced at one CPU on Linux: 1 run in 20 on the old code, 0 in 20 after); a new case sends the signal at each of the three steps of start-up, so no timer is involved. Pack cloud-forensics.

### Fixed: the encrypted-containers pack's archive skill lists the program it names

`archives/protected` names `7z` and now lists it in `requires_host`; the program is declared by the base pack, which the pack depends on, so the pack's own requirements are unchanged. The last line of `tests/pack-links.pending` is gone. Pack encrypted-containers.

### Fixed: three tests that failed on hosted runners no longer do

The 12 MiB hub transfer test measured every socket write in the process, so a stopped hub's late forward of a 500 KB trace line to its collector (left over from an earlier test) counted as a line on the seat's link; it now measures the seat's own connections only. The skill-unload suite's failed hand-off case polled files that a running process appends to and parsed a half-written last line (on Linux a reader can see a line before its newline is written); the polling reads now take whole lines only, and the test client waits for the process to exit after SIGKILL as well.
