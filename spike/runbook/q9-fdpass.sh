#!/usr/bin/env bash
# Finding 5: authorization at open vs per read, and fd passing.
# An allowlisted binary (fdopener) opens the file, then execs a NON-allowlisted
# reader (head) that inherits the open fd 3 and reads it. Compare:
#   - open-gating only (round 1): inherited fd yields REAL bytes (the leak).
#   - -gate-reads (round 2):      inherited fd yields REDACTED (per-read re-auth).
set -u
. "$(dirname "$0")/common.sh"

TOOLS="$(cd "$(dirname "$0")/../tools" && pwd)"
build
CGO_ENABLED=0 go build -o "$SPIKE_ROOT/fdopener" "$TOOLS/fdopener" || exit 1

rm -rf "$BACKING" "$MNT"; mkdir -p "$MNT"; seed
# Allowlist ONLY fdopener by hash; head is not allowlisted.
OPENERHASH=$(sha256sum "$SPIKE_ROOT/fdopener" | awk '{print $1}')
echo "allowlisted fdopener sha256 = $OPENERHASH"

run_case() {
  local label="$1"; shift
  echo "===== $label ====="
  unmount_stale
  "$BIN" -backing "$BACKING" -mount "$MNT" -log "$LOG" -allow-other -hash-exe \
    -allow-sha256 "$OPENERHASH" "$@" > "$SPIKE_ROOT/daemon.out" 2>&1 &
  for _ in $(seq 1 50); do mountpoint -q "$MNT" && break; sleep 0.1; done
  CID=$(docker run -d --rm \
    -v "$MNT:/secrets:rshared" \
    -v "$SPIKE_ROOT/fdopener:/usr/local/bin/fdopener:ro" \
    "$IMAGE" sleep 300)
  echo "-- baseline: fdopener reads it entirely (allowlisted) => expect REAL --"
  docker exec "$CID" fdopener /secrets/gh/hosts.yml
  echo "-- fdopener opens, then non-allowlisted head reads inherited fd via stdin --"
  docker exec "$CID" fdopener /secrets/gh/hosts.yml /usr/bin/head -c 400 || true
  docker rm -f "$CID" >/dev/null 2>&1 || true
  stop_daemon
}

run_case "open-gating only (round 1 behaviour)"
run_case "per-read gating (-gate-reads, round 2)" -gate-reads
