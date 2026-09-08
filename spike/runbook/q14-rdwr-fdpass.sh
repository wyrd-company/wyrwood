#!/usr/bin/env bash
# Round 3, finding 2 (open-gating leaks a writable inherited handle).
# An allowlisted fdopener opens the credential O_RDWR, then execs a
# NON-allowlisted head that reads the inherited handle via stdin.
#   - open-gating only: the inherited O_RDWR handle yields REAL bytes.
#   - -gate-reads:      the same handle yields REDACTED (read re-authorized),
#                       and a write attempt through it is refused.
set -u
. "$(dirname "$0")/common.sh"

TOOLS="$(cd "$(dirname "$0")/../tools" && pwd)"
build
(cd "$TOOLS/fdopener" && CGO_ENABLED=0 go build -o "$SPIKE_ROOT/fdopener" .) || exit 1
rm -rf "$BACKING" "$MNT"; mkdir -p "$MNT"; seed
OPENERHASH=$(sha256sum "$SPIKE_ROOT/fdopener" | awk '{print $1}')

run_case() {
  local label="$1"; shift
  echo "===== $label ====="
  unmount_stale
  "$BIN" -backing "$BACKING" -mount "$MNT" -log "$LOG" -allow-other -hash-exe \
    -allow-sha256 "$OPENERHASH" "$@" > "$SPIKE_ROOT/daemon.out" 2>&1 &
  for _ in $(seq 1 50); do mountpoint -q "$MNT" && break; sleep 0.1; done
  CID=$(docker run -d --rm --user "$(id -u):$(id -g)" \
    -v "$MNT:/secrets:${PROP:-rshared}" \
    -v "$SPIKE_ROOT/fdopener:/usr/local/bin/fdopener:ro" \
    "$IMAGE" sleep 300)
  echo "-- non-allowlisted reader reads AND writes the inherited O_RDWR handle (stdin=fd) --"
  docker exec -e RDWR=1 "$CID" fdopener /secrets/gh/hosts.yml \
    /bin/sh -c 'head -c 200 <&0; echo; echo pwned 1>&0 2>/dev/null && echo "WRITE ACCEPTED (leak)" || echo "write denied"' || true
  docker rm -f "$CID" >/dev/null 2>&1; stop_daemon
}

run_case "open-gating only (round 1/2 handle)"
run_case "per-read + per-write gating (-gate-reads)" -gate-reads
