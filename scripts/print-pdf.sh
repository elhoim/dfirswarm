#!/usr/bin/env bash
# Print an HTML file to PDF through Chrome, Chromium or Edge.
#
#   scripts/print-pdf.sh <html> [pdf]
#
# Not a dependency of the report: without a browser the HTML still prints
# from File > Print > Save as PDF. Headless Chrome writes the file and then
# sometimes does not exit, so this waits until the PDF stops growing and
# then kills the process. macOS has no `timeout`, hence the loop.
set -euo pipefail

html="${1:-}"
if [[ -z "$html" || ! -f "$html" ]]; then
  echo "print-pdf.sh: need an HTML file" >&2
  exit 2
fi
pdf="${2:-${html%.html}.pdf}"

find_print_browser() {
  local candidate
  for candidate in \
    "${SWARM_CHROME:-}" \
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
    "/Applications/Chromium.app/Contents/MacOS/Chromium" \
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge" \
    "$(command -v google-chrome 2>/dev/null || true)" \
    "$(command -v google-chrome-stable 2>/dev/null || true)" \
    "$(command -v chromium 2>/dev/null || true)" \
    "$(command -v chromium-browser 2>/dev/null || true)" \
    "$(command -v microsoft-edge 2>/dev/null || true)"
  do
    [[ -n "$candidate" && -x "$candidate" ]] && { printf '%s\n' "$candidate"; return 0; }
  done
  return 1
}

browser=""
if ! browser="$(find_print_browser)"; then
  echo "No Chrome, Chromium or Edge found, so there is no PDF. The HTML prints correctly from any browser (File > Print > Save as PDF); set SWARM_CHROME to a browser binary to have this command do it." >&2
  exit 3
fi

: "${SWARM_PDF_TIMEOUT_SEC:=60}"
profile="$(mktemp -d)"
rm -f "$pdf"
# The browser's own header and footer stay on: they are the only source of
# page numbers. @page margin boxes are unimplemented in Chrome, and a
# position:fixed running head is anchored to the first page there, so it
# prints over the content of every page after it.
"$browser" --headless=new --disable-gpu --no-sandbox --no-first-run \
  --user-data-dir="$profile" \
  --print-to-pdf="$pdf" "file://$html" >/dev/null 2>&1 &
chrome_pid=$!
waited=0
size=0
last=-1
settle=0
while (( waited < SWARM_PDF_TIMEOUT_SEC )); do
  kill -0 "$chrome_pid" 2>/dev/null || break
  size="$( [[ -f "$pdf" ]] && wc -c < "$pdf" | tr -d ' ' || echo 0 )"
  if [[ "$size" -gt 0 && "$size" == "$last" ]]; then
    settle=$((settle + 1))
    (( settle >= 2 )) && break
  else
    settle=0
  fi
  last="$size"
  sleep 1
  waited=$((waited + 1))
done
kill "$chrome_pid" 2>/dev/null || true
wait "$chrome_pid" 2>/dev/null || true
rm -rf "$profile"
if [[ -s "$pdf" ]]; then
  echo "Wrote $pdf ($(wc -c < "$pdf" | tr -d ' ') bytes, via $(basename "$browser"))"
  exit 0
fi
echo "$(basename "$browser") did not produce a PDF. The HTML is there; print it from a browser." >&2
exit 3
