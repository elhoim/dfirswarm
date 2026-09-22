#!/usr/bin/env bash
# Fixture test: mailbox, lock conflict, write-guard, sentinel stop, web app API.
# No live model. Safe when Herdr, Pi, or API keys are missing.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec node --experimental-strip-types --test "$ROOT/tests/dry-run.test.ts" "$ROOT/tests/ui-server.test.ts"
