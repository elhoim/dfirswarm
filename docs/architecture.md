# Architecture

What runs where: the operator's scripts, the Herdr panes, the Pi extension, the sandbox on disk, the egress proxy and the web app.


```mermaid
flowchart TB
  subgraph OP["Operator"]
    CLI["scripts/swarm.sh<br/>start · list · status · stop · reap · netcheck · ui"]
    TAIL["scripts/watch.sh<br/>scripts/await-done.sh"]
    BROWSER["Any browser on the LAN"]
  end

  subgraph HERDR["Herdr workspace (one pane per agent, √N grid, tab/workspace spill)"]
    P0["pane · AGENT_ID=s1a2b00<br/>pi -e agent-swarm.ts"]
    P1["pane · AGENT_ID=s1a2b01<br/>pi -e agent-swarm.ts"]
    PN["… up to N=30"]
  end

  subgraph EXT["Pi extension (extensions/)"]
    TOOLS["agent-swarm.ts tools<br/>post · inbox · wait · list_team · budget<br/>claim_file · release_file · claims<br/>thread_open · thread_join<br/>file_history · file_diff · file_restore · done"]
    GUARD["write guard<br/>tool_call hook blocks edit/write<br/>bash bracketed by a hash snapshot"]
    USAGE["turn_end → sessionManager.getEntries()<br/>→ budget.json, cap + wall steer, harness stop"]
    SYS["system posts<br/>violations · caps · sentinel"]
    PW["playwright-tool.ts<br/>(only with --playwright)"]
  end

  subgraph FS["runs/ID/ · isolated cwd · the contract"]
    SWARMMD["SWARM.md · team.json · budget.json<br/>(harness-owned: agents never write these)"]
    THREADS["threads/main/000001-s1a2b00.md …<br/>threads/NAME/meta.json · inbox/ID/cursors.json"]
    LOCKS["locks/sha256.json · locks/.table.lock"]
    WORK["work/ (artifacts) · history/hash/000001.bin"]
    DONE["done/SWARM_DONE · done/agents/ID.done|.dead"]
    EVENTS["traces/events.jsonl · layout.json · netguard.log"]
  end

  subgraph NET["Egress"]
    NG["scripts/netguard.sh sidecar<br/>allowlisting CONNECT proxy 127.0.0.1:&lt;port&gt; (one per swarm, from 43178 up)<br/>+ PATH shim sandbox/bin/pi"]
    PROVIDER["Provider API hosts<br/>(4 defaults + the selected model's)"]
    DENY["everything else → 403 / ENETUNREACH"]
  end

  UI["scripts/ui-server.ts<br/>node:http · JSON API · SSE /api/events · static ui/dist"]
  REAP["scripts/reap.sh<br/>silence > timeout → .dead + drop locks"]
  CHROME["headless Chromium<br/>work/.browser/*.png"]

  CLI -->|herdr workspace create / pane split / agent start / agent prompt| HERDR
  CLI -->|renders SWARM.md from the goal document + team.json, budget.json, .pi/SYSTEM.md| FS
  CLI -->|starts| NG
  P0 & P1 & PN --> EXT
  EXT <-->|read/write protocol files| FS
  EXT -->|HTTPS_PROXY| NG
  NG --> PROVIDER
  NG -.-> DENY
  PW --> CHROME --> WORK
  UI -->|fs.watch recursive| FS
  UI -->|bash scripts/swarm.sh start / stop / reap| CLI
  BROWSER <-->|HTTP + SSE, port 43173, 127.0.0.1 by default<br/>reads open, mutations need the token| UI
  TAIL --> FS
  TAIL -->|polls| REAP
  TAIL -->|runs the goal's ## Checks| FS
  UI -->|Reap stalled| REAP
  REAP --> DONE
  REAP -.->|--stop: herdr agent get → pane close| HERDR
```

Reading the diagram:

- **Spawner** (`scripts/swarm.sh start`) is the only authority. It allocates a unique swarm id (`s` + 4 hex), frames the goal document as `SWARM.md`, writes `team.json` / `budget.json`, creates one Herdr workspace with `--cwd` pointed at the sandbox, splits one pane per agent, starts `pi` in each pane with `AGENT_ID` set, and sends the same kickoff prompt to every agent. It assigns no roles: who reviews whom is the goal's business.
- **Agents** are plain Pi sessions with `--tools` restricted to `read,bash,edit,write` plus the extension tools. All swarm behaviour lives in `extensions/agent-swarm.ts` + `extensions/protocol.ts`; nothing is patched into Pi or Herdr.
- **The harness has a voice.** It posts on the board as `system`: a claim violation, the spend cap, the wall clock, the sentinel. Those used to reach only `events.jsonl`, so a peer could not learn from the board that someone had stomped a file or that the money had run out.
- **The filesystem is the protocol.** Posts are files, locks are files, done is a file, the log is a file. Anything that can `ls` the sandbox can observe or drive the swarm.
- **The web app** never writes protocol files itself (one exception: operator file restore, which goes through the same `protocol.ts` claim path). Every mutation shells out to `scripts/swarm.sh`, so the UI and the terminal can never disagree.
- **Netguard** is on by default and gives each `pi` process egress to the provider host only. **Reaper** and **Playwright** are optional side paths.
