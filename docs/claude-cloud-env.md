# Running the swarm in a Claude Code cloud environment

How to configure an Anthropic-hosted Claude Code cloud environment (the **Add cloud environment** dialog at claude.ai/code) so a cloud session can run this repo: Herdr + Pi agents, `scripts/swarm.sh`, the web UI, Playwright/Chromium. Facts below come from [Configure cloud environments](https://code.claude.com/docs/en/cloud-environments) and [Use Claude Code in the cloud](https://code.claude.com/docs/en/claude-code-on-the-web) (read 2026-09-16); anything the docs do not state is marked **UNKNOWN**.

## What the VM gives you

- Fresh Ubuntu 24.04 x86_64 VM per session, ~4 vCPU / 16 GB RAM / 30 GB disk, no GPU listed. Node 20/21/22 pre-installed (`/opt/node22` on `PATH`), plus `jq`, `python3`, `git`, `gh`, `tmux`, Docker. Chromium/Chrome: **UNKNOWN** (only `chromedriver` is listed).
- The setup script runs **as root**, before Claude Code launches, must exit 0 and finish in roughly **five minutes**. Its result is snapshotted and reused for later sessions (files only, not processes; rebuilt when the script or the domain list changes, or after ~7 days). Whether the repo is already checked out in the script's cwd is **UNKNOWN**; the script tolerates both.
- All egress goes through Anthropic's security proxy. Network access levels: None / Trusted (package registries, GitHub, cloud SDKs) / Full / Custom. GitHub goes through a separate proxy that only serves **release assets of repositories attached to the session**.
- No shell for you, no documented port forwarding or preview URL; Claude runs every command. The home directory does not persist across sessions.

## Dialog fields

| Field | Value |
| --- | --- |
| **Name** | `dfirswarm` |
| **Network access** | **Custom**, tick *Also include default list of common package managers*, then list: `api.deepseek.com`, `api.openai.com`, `api.x.ai`, `herdr.dev`, `pi.dev`, `cdn.playwright.dev`, `playwright.download.prss.microsoft.com`. Trusted alone lacks the provider APIs, Herdr and the Playwright CDN; Full works but drops the network-level allowlist. |
| **Environment variables** | Non-secret: `SWARM_UI_PORT=43173`, `SWARM_UI_HOST=127.0.0.1`, `SWARM_STALL_SEC=90`, `HERDR_INSTALL_DIR=/usr/local/bin`, `PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright`, `NODE_USE_ENV_PROXY=1`. Optional `SWARM_RUNS_DIR=/tmp/swarm-runs`, `NODE_OPTIONS=--max-old-space-size=4096`. Provider keys: see below. |
| **Setup script** | Paste [`scripts/cloud-setup.sh`](../scripts/cloud-setup.sh) verbatim. |

### Provider keys (`DEEPSEEK_API_KEY`, `OPENAI_API_KEY`, `XAI_API_KEY`)

`swarm.sh start` now reads the key from **Pi's own store** by default and
passes nothing to the panes. A cloud VM recreates `$HOME` every session, so
`pi /login` does not survive — pass **`--key-from-env`**, which restores the old
behaviour: the variable for the model prefix must be non-empty in the shell that
runs the command, and it is handed to each Herdr pane with `--env`. Nothing is
written to disk; the key is briefly visible in `ps` to this user. See
[ADR 0003](adr/0003-the-provider-key-comes-from-pis-own-store.md).

1. **Environment variables field (works today).** The docs warn that anyone who uses the environment can read the values; environments are personal to your account, so on a solo Pro/Max account that is you. Acceptable with per-environment, spend-limited, rotatable keys; never share the session publicly and never print `env` in a session.
2. **API credentials (Pro/Max only, official secret path).** Edit the saved environment → **API credentials** → Bearer credential for `api.deepseek.com` with header `Authorization` / prefix `Bearer`. The proxy attaches the key after the request leaves the VM, so the key never enters the session. Set `DEEPSEEK_API_KEY=proxy-injected` as a placeholder so `swarm.sh` proceeds. Whether the proxy **replaces** Pi's existing `Authorization` header is **UNKNOWN**: test with `curl -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer proxy-injected' https://api.deepseek.com/models` (200 = works, 401 = stay with option 1).
3. Writing `~/.pi/agent/auth.json` from the setup script has the same visibility as option 1 plus a copy in the cached snapshot; `pi /login` does not persist because `~` is recreated every session. Neither is recommended.

## Runtime caveats

- **Herdr is headless-capable**: `herdr server` runs the background server that owns the PTYs; no attached client is needed. Start it every session: `tmux new-session -d -s herdr 'herdr server'`. Processes are not part of the snapshot.
- **Herdr install may 403**: the binary is a GitHub release asset of `herdrdev/herdr`, which is not attached to the session. The setup script only warns; test first. Without `herdr` the swarm cannot start (`BLOCKER: missing herdr`); `npm test` and `--no-start` still work.
- **netguard**: use `--no-netguard`. `unshare -rn` availability is **UNKNOWN**, and more importantly the local netguard proxy opens direct TCP to the provider, which may not route through Anthropic's security proxy (transparent vs env-var proxy is **UNKNOWN**). The Custom allowlist already enforces provider-only egress at the network layer. Try `scripts/swarm.sh netcheck` once; keep the default only if it prints `ALLOW`.
- **Playwright**: browsers live in `/opt/ms-playwright` (shared, root-installed with `--with-deps`); the extension picks them up via `PLAYWRIGHT_BROWSERS_PATH`. Or set `BROWSER_CHECK_EXECUTABLE` if the image already has Chromium.
- **Web UI**: no browser reaches the VM, so the mutating routes are unreachable anyway; `SWARM_UI_TOKEN=` keeps `curl` simple. Run `scripts/swarm.sh ui --host 127.0.0.1` in tmux and verify with `curl http://127.0.0.1:43173/api/swarms` and `npx playwright screenshot --full-page <url> out.png`, then commit the screenshot.
- **Persistence**: `runs/` disappears with the VM. Copy run evidence into the branch before the session expires.
- **Scale**: N=2–10 expected fine; N=30 (30 Pi processes) untested on 16 GB.

## Session recipe (put in `CLAUDE.md`)

```bash
# every session
bash scripts/cloud-setup.sh project
tmux has-session -t herdr 2>/dev/null || tmux new-session -d -s herdr 'herdr server'
# dry run
npm test && bash tests/reap.test.sh && bash tests/netguard.test.sh
# live N=2
scripts/swarm.sh start --model deepseek/deepseek-v4-pro --cap-usd 1 --n 2 \
  --no-netguard --key-from-env --goal-file prompts/goals/hello.md
scripts/await-done.sh --sandbox runs/<id> --timeout 480 && scripts/swarm.sh stop <id>
# UI
tmux new-session -d -s swarm-ui 'scripts/swarm.sh ui --port 43173 --host 127.0.0.1 --no-build'
curl -s http://127.0.0.1:43173/api/health
```

## Test first (UNKNOWN list)

1. Herdr release-asset download through the GitHub proxy (403?).
2. Setup script runtime under five minutes with Chromium + `npm ci` + `ui:build`.
3. Setup script cwd and the session user (root or not); `herdr integration install pi` is per user.
4. API credential overriding an existing `Authorization` header.
5. Transparent vs env-var proxy; `unshare -rn`; Node minor version for `NODE_USE_ENV_PROXY`.
6. Pre-installed Chromium; external UI reachability; N=30 memory; session idle expiry during an 8-minute swarm.
