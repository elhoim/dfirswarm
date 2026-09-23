# Running the swarm on a Linux server

Written against Ubuntu 24.04.5 (kernel 6.8) on a 2 vCPU / 3 GB droplet, after
the first real run there: [run 4 of the Web Server
case](use-cases/dfir-web-server-case/run-4-linux.md). Everything below was
measured on that host. What the kernel can enforce and how is in
[linux-plan.md](linux-plan.md); this page is what an operator has to get
right.

## Packages

```
apt-get install -y zsh bubblewrap util-linux iproute2 sqlite3 p7zip-full jq python3
```

Node ≥ 22.6 from your usual source, then Pi and Herdr as the
[quick start](quick-start.md) has them. Nothing forensic: the agents install
what a case needs, inside the run.

## The account the swarm runs as

**Not root, and its login shell must be zsh or bash.** Herdr starts every
pane with a login shell, and the write guard is a hook that shell reads at
startup: a zsh reads `$ZDOTDIR/.zshenv`, and a bash reads the `.bashrc` (or,
as a login shell, `.bash_profile`) under the `HOME` the pane is given. The
kickoff reads the login shell from the account database and moves the panes'
`HOME` only for bash; both hooks put it back before anything else runs. Any
other shell reads neither, and every pane would come up unguarded, so the
kickoff refuses to start rather than let that happen silently.

```
useradd -m -s /bin/bash swarm   # or /usr/bin/zsh
chsh -s /usr/bin/zsh swarm      # to change an account that already exists
```

With zsh, give the account a `~/.zshrc`, even an empty one. Ubuntu's zsh opens its
new-user wizard in every interactive shell whose home has none, and the
wizard reads the first line typed into the pane as its menu answer: the
`pi` command, which then never runs, and the kickoff times out "waiting for
agent startup" with four idle panes. The pane hook now keeps its own empty
`.zshrc` when the home has none, so a run survives it either way; the file
in the home is still the right fix.

```
touch /home/swarm/.zshrc
```

Herdr passes **its own** `SHELL` to the panes, so start its server after the
shell is set, and set it explicitly if you are unsure. It has to be the
account's login shell: the kickoff cannot see the server's `SHELL`, and a
pane shell that differs from the account's is unguarded (the record says so),
or, on a bash account, keeps the hook's `HOME`:

```
SHELL=/usr/bin/zsh tmux new-session -d -s herdr 'SHELL=/usr/bin/zsh herdr server'
```

## What the host must allow

| | Why | How to check |
| --- | --- | --- |
| Landlock (kernel ≥ 5.13) | the write allowlist | `python3 scripts/landlock.py --dry-run -- true` |
| Unprivileged user namespaces | read-only root, masks, the network namespace | `unshare -rm true` |
| `bubblewrap` | the namespace layer outside a pane | `bwrap --version` |

Ubuntu 24.04 switches unprivileged user namespaces off for programs without
an AppArmor profile. Without them the run still gets Landlock, and the record
says what could not be enforced (`herdr_socket: unenforced`,
`pi_extensions: writable`, `netguard_mode: proxy-only`). To turn them on:

```
sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

That is a host hardening setting; it is the operator's call, not the
harness's, and the harness never changes it.

## Inside a pane, the guard is in place

A pane's shell re-runs itself under the guard with `--in-place`: `unshare`
without `--fork`, so the shell keeps its own pid and the terminal keeps
watching a shell. bubblewrap cannot do that — it always forks, and Herdr then
refuses to start an agent there ("agent target pane is not an available
shell"). The cost is the pid namespace: inside a pane, peers' processes stay
visible. Everything else — the write allowlist, the read-only evidence, the
masked terminal socket, the network namespace — applies.

## Evidence without a copy

`--inputs-bind` makes `inputs/` a link to the evidence and holds the source
itself read-only in every pane. 26 GB is then ready in the time it takes to
hash it, with no second copy on the disk. Two things to know:

- There is no pristine clone, so the sweep can detect a change and cannot
  heal it. The kernel guard is what stops the change; the flag refuses to run
  without one.
- `inputs/` is a symlink, so a goal check that walks it needs `find -H inputs`
  (follow the link named on the command line) rather than `find inputs`, which
  counts zero files through a link. The same holds under `--inputs-bind` on macOS.

## Watching it, and stopping it

The web console binds loopback; reach it over SSH rather than opening a port:

```
ssh -N -L 43173:127.0.0.1:43173 you@host
```

The run's daemons are detached from whatever terminal started the kickoff
(`setsid`), so closing your SSH session or the tmux window does not take the
egress proxy or the trace collector with it. `swarm.sh stop <id>` ends them;
after it, `pgrep -f 'trace-collector|trace-gate|nudge-broker|netguard-proxy'`
should find nothing.

## What the record will say on a good host

```
write_guard: linux            the namespace and Landlock both applied
write_guard_measured: kernel  every pane's own probe agreed
herdr_socket: masked          the terminal's control socket is hidden from the panes
pi_extensions: read-only      nothing can be dropped into Pi's extensions
attribution: ancestry         who wrote a line is decided by the kernel, not by a token
netguard_mode: netns          a connection outside the allowlist has no route
```

If any of those says something weaker, the host could not give it and the
report's custody section will say which.
