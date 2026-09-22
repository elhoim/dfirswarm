#!/usr/bin/env bash
# Run every slice-2 fixture. No model, no keys, no Herdr.
#   playwright tool     tests/playwright-tool.test.ts  (browser steps skip without Chromium)
#   real Pi loader      tests/pi-load.test.ts          (skips without Pi; set PI_PACKAGE_DIR)
#   definition of done  tests/await-done.test.sh
#   stall reaper        tests/reap.test.sh
#   netguard            tests/netguard.test.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

node --experimental-strip-types --test tests/playwright-tool.test.ts tests/pi-load.test.ts
bash tests/await-done.test.sh
bash tests/reap.test.sh
bash tests/netguard.test.sh
echo "slice2: all fixtures passed"
