#!/bin/sh
# Mirrors the native CLI shape exactly rather than inventing a parallel
# env-var flag language - first arg picks the mode (matching main.rs's own
# --inline vs <interface> split), everything after that is forwarded
# verbatim to the dpi-lab binary.
set -e

mode="$1"
shift || true

case "$mode" in
  inline)
    exec /app/dpi-lab --inline "$@"
    ;;
  passive)
    exec /app/dpi-lab "$@"
    ;;
  ui)
    exec /app/dpi-lab-ui "$@"
    ;;
  *)
    echo "usage: docker run ... <image> <inline|passive|ui> [args...]" >&2
    echo "  inline:  runs --inline (Linux NFQUEUE mode, no interface arg)" >&2
    echo "  passive: runs passive capture, \$1 after 'passive' is the interface" >&2
    echo "  ui:      runs dpi-lab-ui (unprivileged web UI), e.g. --bind 0.0.0.0:8080" >&2
    exit 1
    ;;
esac
