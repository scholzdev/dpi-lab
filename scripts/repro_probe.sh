#!/usr/bin/env bash
# Reproduces the active-probing logic (src/probe.rs) in isolation: confirms a
# real local SOCKS5 responder, and correctly refuses to confirm one that just
# sends noise back. No root, no capture interface, no lab traffic needed --
# pure component-level repro (127.0.0.1 only), safe to run anywhere, same
# thing CI would run.
#
# Usage: ./scripts/repro_probe.sh
set -euo pipefail
cd "$(dirname "$0")/.."

echo "--- probe::probe() against a real SOCKS5 responder and a non-matching one ---"
echo "--- (see src/probe.rs tests for the exact listener behavior) ---"
cargo test --quiet probe:: -- --nocapture
