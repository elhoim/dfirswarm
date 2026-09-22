# Run 4: the same case on Linux, and the nine things that had to be fixed first

Runs 1–3 were macOS. This one is a DigitalOcean droplet — Ubuntu 24.04.5,
kernel 6.8, 2 vCPU, 3 GB RAM — reached over SSH, with no desktop, no Xcode and
no seatbelt. It is the first run of the swarm on the platform the Linux work
(PR #10) was built for, and the point of it was not the case: it was to find
out what the harness does on a real server that a container and a test suite
cannot tell you.

It found nine defects. Seven were in the harness, two of them security
defects; all nine are fixed in this branch, and every fix was measured on the
server before and after.

| | Run 1 (`s2cb9`, macOS) | Run 4 (`s3096`, Ubuntu) |
| --- | --- | --- |
| Started → sentinel | 14.5 min | 21:44:40Z → 21:58:46Z (**14.1 min**) |
| Team | 7 agents, `gpt-5.4` ×4 + `deepseek-v4-pro` ×3 | **4 agents**, all `openai/gpt-5.4-mini` |
| Evidence | 26 GB copied into `inputs/` | 26 GB **bound in place** (`--inputs-bind`), never copied |
| Write guard | seatbelt | Landlock (ABI 4), then Landlock inside a user namespace |
| Egress | proxy-only (advisory) | **network namespace** (a direct connection has no route) |
| Attribution | token in the pane's environment | **process ancestry** through the trace gate |
| Cost | $7.98, 420 calls, 27.1M tokens | **$4.81**, 417 calls, 42.9M tokens |
| Checks | 9/9 | **6/9** |
| Timeline | 61 rows | 60 rows |
| Tools installed by the agents | Sleuth Kit etc. pre-installed on the host | `python-evtx`, `pefile`, `construct` pulled from pypi into the run, one tool forged (`evtx_dump`) |

## What the swarm found

The same intrusion runs 1–3 reported, from a smaller team on a smaller model:
DVWA on XAMPP breached from `192.168.56.102` with `sqlmap`, web shells
(`c99.php`, `phpshell.php`, `phpshell2.php`, `webshells.zip`) left in the
DVWA tree, two local accounts added (`user1` RID 1005, `hacker` RID 1006),
and staged Meterpreter in memory (`Evaling main meterpreter stage`). The
report is [`run-4-linux/report.md`](run-4-linux/report.md), the timeline
[`run-4-linux/timeline.md`](run-4-linux/timeline.md).

It lost three checks, and the reasons are worth separating. Two are the
team's: no `## Bonus` section and no stated hypothesis, both asked for by the
goal. The third is the harness's, and is defect 7 below.

The report is published as the swarm wrote it, and it does not meet this
repository's own citation lint: three of its eight sections cite nothing a
reader could check. `tests/report.test.ts` records that by name and asserts
the number, so the artifact stays what the run produced and the shortfall
cannot grow quietly. Seven agents on larger models, in runs 1–3, cited every
section.

The evidence was not touched: zero `inputs_violation` events, and the disk
image still hashes to `a584de7f…cce6f9`, the value the challenge publishes.

## The nine defects

**1. The kickoff's own summary contradicted the record.** The `Inputs:` line
said "kernel guard: none (detect + heal only)" while the manifest, the pane
hook and the run record all said `landlock`. `inputs_guard_label` had no case
for the two Linux modes. Cosmetic, and exactly the kind of thing an examiner
would quote in a report.

**2. A fresh Pi has no `extensions/` directory,** so the carve that makes it
read-only was skipped and the record said `not-applicable` — while a pane
could have created the directory inside the writable agent directory and
dropped code in it, which every later Pi run on the machine would load. The
kickoff creates it before carving.

**3. The daemons died with the terminal.** The kickoff was started in a tmux
window that closed when the kickoff returned. `nohup` only makes a process
ignore SIGHUP; it keeps the controlling terminal. The netguard proxy went
down with the window, every agent lost its egress at that moment, and four
panes sat retrying `Connection error.` while the record said the guard was
on. Measured both ways on the server: with `nohup` the proxy is gone once the
window closes, with `setsid` it is still listening.

**4. The write guard never reached a pane.** Herdr starts each pane with the
login shell from the account database; that account's shell was bash, and the
guard is a hook only a zsh reads. Every pane came up unguarded, every pane's
own probe said `none`, and the record said `write_guard: linux`. macOS has
made zsh the login shell since Catalina, which is why three macOS runs never
showed it. The preflight refuses it now and names the `chsh` that fixes it.
A second copy of the same trap: Herdr passes its *server's* `SHELL` to the
panes, so the server has to be started after the shell is changed.

**5. The record said what the host could do, not what the panes got.** That
is the same mistake in the record that defects 2–4 were in the code. Every
agent already probes its own guard at session start; the kickoff now reads
those probes and writes `write_guard_measured` — `kernel`, `partial`, `none`
or `unmeasured` — with a WARN when it is not `kernel`, and the report has a
custody row for it. This run's record says `none`, honestly, because of
defect 6.

**6. `--inputs-bind` left the evidence writable under Landlock.** *(security)*
Landlock only grants, so fsguard carves a read-only path out of a writable one
by handing every sibling the region's rights and the ancestors a listing.
The sibling walk compared each child by the name it was listed under while the
carved paths were recorded canonically — and under `--inputs-bind`, `inputs/`
is a symlink, so it matched nothing, was handed the run's write rights, and
`O_PATH` followed it to the evidence directory's inode. Landlock unions
rights per inode, so that grant overruled the carve. Measured on the server:
`touch` into the bound evidence, through the link and at its target, both
allowed before the fix and refused after. `tests/write-guard.test.sh` has the
case.

**7. The pane's probe could not recognise Landlock.** It read EPERM and EROFS
as the kernel and EACCES as "the permission bits alone" — but Landlock
refuses with EACCES (measured on 6.8). So a pane under a working Landlock
guard reported `none`. The probe now reads the guard mode it was started
under, which only the guard itself sets, and counts EACCES as the kernel
there. This is also why a goal check written the obvious way
(`find inputs -type f`) fails under `--inputs-bind`: `inputs/` is a symlink
and `find` does not follow it without `-L`. That is the third lost check.

**8. Herdr refused to start an agent in a guarded pane.** *(the strongest
guard was unusable)* `agent target pane w1:p1 is not an available shell`.
bubblewrap always forks — it keeps a supervisor outside the namespace — so
the process the terminal watches is `bwrap`, not a shell. fsguard takes
`--in-place` now and uses `unshare` without `--fork`, which execs straight
through to the shell. The cost is the pid namespace, which cannot exist
without a child. With it, a verification run on the same server recorded
`write_guard: linux`, `write_guard_measured: kernel` in every pane,
`herdr_socket: masked`, `pi_extensions: read-only`.

**9. `stop` left every daemon running.** *(operational)* Backgrounding a
shell function forks a subshell, so when the `nohup` call sites became calls
to a helper function, `$!` began naming that subshell rather than the daemon.
The pid files held pids that were already gone; `stop` killed nothing and
deleted the files, and the daemons became unreachable. Seventeen had piled up
over five kickoffs. Measured after the fix: three daemons for a run, zero
left after `stop`.

## What this says about the platform on Linux

The guarantees hold, and on this host two of them are stronger than on macOS:
egress is refused by the kernel rather than advised by a proxy, and who wrote
a trace line is decided by the kernel's `SO_PEERCRED` and the process tree
rather than by a token a peer could read. What a server costs you is the pid
namespace when the terminal has to keep the pane, and the fact that every one
of these defects was invisible to CI: both Docker tiers passed 15/15 shell
suites and 248 node tests through all nine of them, because a container has
no Herdr, no login shell of its own and no terminal that closes.

Files in [`run-4-linux/`](run-4-linux/): the report, the timeline, the run
record for both runs (`record.jsonl`), the ledger (`budget.json`), the guard
plan the panes were started with (`fsguard-plan.txt`), and the tool counts.
