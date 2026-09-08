#!/usr/bin/env bash
# Round 3, finding 3 (mtime-restore defeats the cache). An allowlisted binary
# at a writable path reads real bytes; the attacker then overwrites its bytes
# with a different (non-allowlisted) binary but restores the original mtime.
#   -trust-mtime-cache ON  : stale approved hash is returned -> REAL (the bug).
#   default (re-hash)      : bytes are re-hashed -> REDACTED (the fix).
set -u
. "$(dirname "$0")/common.sh"

build
rm -rf "$BACKING" "$MNT"; mkdir -p "$MNT"; seed
CATHASH=$(docker run --rm "$IMAGE" sha256sum /bin/cat | awk '{print $1}')

run_case() {
  local label="$1"; shift
  echo "===== $label ====="
  unmount_stale
  "$BIN" -backing "$BACKING" -mount "$MNT" -log "$LOG" -allow-other -hash-exe \
    -allow-sha256 "$CATHASH" "$@" > "$SPIKE_ROOT/daemon.out" 2>&1 &
  for _ in $(seq 1 50); do mountpoint -q "$MNT" && break; sleep 0.1; done
  CID=$(docker run -d --rm --user "$(id -u):$(id -g)" -v "$MNT:/secrets:${PROP:-rshared}" "$IMAGE" sleep 300)
  docker exec "$CID" sh -c '
    cp -p /bin/cat /tmp/mutable
    ref=$(stat -c %y /tmp/mutable)
    echo "-- 1. allowlisted bytes at /tmp/mutable: expect REAL --"
    /tmp/mutable /secrets/gh/hosts.yml | head -3
    echo "-- 2. overwrite with head bytes, RESTORE original mtime --"
    cp /usr/bin/head /tmp/mutable
    touch -d "$ref" /tmp/mutable
    stat -c "mtime now: %y" /tmp/mutable
    echo "-- 3. read again (bytes are head, mtime looks unchanged) --"
    /tmp/mutable -c 200 /secrets/gh/hosts.yml
  '
  docker rm -f "$CID" >/dev/null 2>&1; stop_daemon
}

run_case "trust-mtime-cache ON (vulnerable)" -trust-mtime-cache
run_case "default: re-hash every open (fixed)"
