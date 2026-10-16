#!/usr/bin/env bash
# ---
# relationships:
#   validates: Taskfile
# ---

set -euo pipefail

log=$(mktemp)
trap 'rm -f "$log"' EXIT

# Verbose, uncached output exposes prerequisite skips even after a local run.
go test -count=1 -v ./... | tee "$log"

if grep -Eq 'bao executable not available|Docker Engine not reachable|test image .* not present' "$log"; then
  echo "CI requires the OpenBao and real-engine tests; a prerequisite was missing." >&2
  exit 1
fi
