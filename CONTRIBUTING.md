# Contributing

Thanks for looking. This is a small project with strong opinions; the
opinions are written down so you do not have to guess them.

## What it is, in one line

N peer coding agents share one sandbox and coordinate on a file board; the
harness enforces leases, caps, a stop signal and a log. Everything the swarm
may decide, it decides on the board; everything that must not be negotiable
lives in the harness. Read [CONTEXT.md](CONTEXT.md) for the vocabulary before
you name anything.

## Setting up

```sh
git clone https://github.com/halilozturkci/dfirswarm && cd dfirswarm
nvm use            # .nvmrc → Node 22
npm ci
npm run typecheck  # server + UI
npm test           # protocol + web API suites, no key, no Herdr
npm run test:bash  # every shell suite: certification, preflight, model teams, reaper, netguard, images, packs, microVM flags
npm run ui:build
# on a host that can boot a microVM (Apple silicon, or Linux with /dev/kvm) and has the base image loaded:
DFIRSWARM_VM_TESTS=1 npm run test:vm   # real VMs, one run end to end with a scripted model
```

That is everything CI runs, and none of it needs a model, a key, Herdr or a
Pi login. CI runs the typecheck, the node suites and the shell suites on
amd64 Linux and on macOS (Apple silicon), and the VM suite on amd64 Linux,
where it boots the base and disk images under KVM. A hosted macOS runner
cannot boot a microVM, so the Apple-silicon VM path is run by hand before a
release. A pull request that touches `images/` or a pack's requirements
also builds every profile for amd64 and two (memory, re) for arm64
(`images.yml`), without booting them. Once a week `image-boot.yml` builds
every profile, boots each as an agent's VM under KVM (the probe, its verdict
and Pi end to end), checks it against its packs with the kickoff's
`imageFit`, and does the same for base on arm64 where that runner has KVM;
it pushes nothing. Actions are pinned by commit, with the tag beside each.
The `spikes/` directory is neither typechecked (`tsconfig.json` covers
`extensions/`, `scripts/` and `tests/`) nor re-run: its scripts record
measurements made once, and they can go stale. The host suites run on
Node 22 (`.nvmrc`), and on exactly 22.19.0, the `engines` floor the pinned Pi
needs, in a job of their own; Pi in a VM runs on the image's Node 24
(`images/base.Dockerfile`), and CI runs the node suites on Node 24 as well.

`npm ci` brings Pi's own package in as a devDependency, for the
extension's types and the loader test (`tests/pi-load.test.ts` loads the
extension through that pinned package's own loader); a real run still needs
[Herdr](https://herdr.dev) and [Pi](https://pi.dev) installed and logged in
on the machine; see the README's quick start. A whole swarm with real
panes and no key is possible with the scripted provider
(`docs/proof-run.md`) — that still needs Herdr.

## Rules of the house

- **Tests live in `tests/`.** Node suites are `node:test` with
  `--experimental-strip-types`; shell suites are plain bash. A change to the
  protocol needs a case in `tests/dry-run.test.ts`; a change to the web API
  needs one in `tests/ui-server.test.ts`; a change to `swarm.sh` usually needs
  one in `tests/swarm-preflight.test.sh` or `tests/model-teams.test.sh`,
  which lift the helper out of the script rather than re-implementing it.
- **Shell scripts must run on bash 3.2** (macOS ships it). No `declare -A`,
  no `${arr[@]}` on a possibly-empty array without the `${arr[@]+"${arr[@]}"}`
  guard, no `mapfile`.
- **No MCP servers in tests.** The suites talk to files and to a local HTTP
  server; nothing else.
- **English everywhere in the repository**: code, comments, commit messages,
  docs, the board prompts. The UI is English-only.
- **The harness owns its files.** If a change lets an agent write
  `SWARM.md`, `budget.json`, `done/` or `locks/` through a tool, it is a bug.
- **Mark what you did not verify.** The docs use **UNKNOWN** for anything
  guessed at. Keep doing that rather than writing a confident sentence.

## Adding a UI state

Seed it into the fixture (`scripts/seed-fixture.ts`) so the web API tests and
`npm run ui:fixture` can show it without a model, then add the screen to
`docs/ui-coverage.md`. Screenshots in the README are captured with Playwright
against real runs; refresh them when the design changes.

## Commits and pull requests

- One change per commit, with a message that says why. The existing history
  reads as release notes; keep it that way.
- AI-assisted commits are welcome. Say so in the trailer
  (`Co-Authored-By:`), as the history already does.
- A pull request should say which suite covers it and, for anything touching
  a live run, which swarm id proved it (`scripts/swarm.sh status <id>`).
- Do not commit anything from `runs/`, `.pi-sessions/` or a real
  provider key. `.gitignore` covers the usual places; look anyway.

## Licence and the name

The project is AGPL-3.0-or-later and is also offered under a
[commercial licence](COMMERCIAL-LICENSE.md). Offering both is something only
a copyright holder may do, which is why contributions are accepted under the
[Contributor License Agreement](CLA.md); you agree to it in the pull request
itself, and the template has the sentence. One agreement covers everything
you send, now and later. It leaves your copyright with you and changes
nothing about your rights as a user of the project. If you are contributing
work your employer has rights in, read § 7 of it before you open the pull
request.

The code is AGPL; the name is not. [TRADEMARK.md](TRADEMARK.md) says what you
may call your own work. The short version: fork freely, and give the fork its
own name.

## Reporting a security problem

See [SECURITY.md](SECURITY.md). Do not open a public issue for it.
