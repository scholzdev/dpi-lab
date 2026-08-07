#!/usr/bin/env bash
# Reproduces the signature-match -> RST-injection block from writeup.md §4.2,
# end to end, live: starts the real capture loop, fires a real request at a
# real domain, shows the forged RST winning the race.
#
# This is a LIVE repro against real network egress -- needs root (raw socket
# for --inject) and only makes sense run against infrastructure you own. It
# does not touch config/*.yml; the block rule is passed via --block-sig so
# your real block lists are untouched.
#
# Usage: sudo ./scripts/repro_sig_block.sh [interface] [target-url]
set -euo pipefail

IFACE="${1:-$(route -n get default 2>/dev/null | awk '/interface: /{print $2}')}"
TARGET="${2:-https://florianscholz.dev/}"
KEYWORD="repro-test-$$"

if [[ -z "$IFACE" ]]; then
    echo "couldn't auto-detect interface -- pass one: sudo $0 <interface> [target-url]" >&2
    exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
    echo "needs root (raw socket for --inject) -- rerun with sudo" >&2
    exit 1
fi

echo "own-lab-only: this fires --inject at $TARGET over $IFACE."
echo "make sure that's infrastructure you own. Ctrl-C now to abort, continuing in 3s..."
sleep 3

cd "$(dirname "$0")/.."
cargo build --quiet

./target/debug/dpi-lab "$IFACE" --inject --block-sig "$KEYWORD" &
DPI_PID=$!
trap 'kill "$DPI_PID" 2>/dev/null; wait "$DPI_PID" 2>/dev/null' EXIT
sleep 1 # let the capture loop come up before we send anything

echo "--- expect: [signature] $KEYWORD ... -> [inject] RST sent -> curl reset ---"
curl -sv --max-time 5 "${TARGET}?q=${KEYWORD}" || true

echo "done."
