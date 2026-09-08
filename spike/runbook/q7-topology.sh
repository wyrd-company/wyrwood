#!/usr/bin/env bash
# Finding 2 + 7: safe export topology and the daemon-down window under it.
# Round 1 B2 bound all of $SPIKE_ROOT (which holds backing/), so the container
# could read the real files without FUSE. Here the exported parent contains
# ONLY the mountpoint; backing storage lives outside it. Then, with the daemon
# down, prove reads under the export fail closed rather than exposing backing.
set -u
. "$(dirname "$0")/common.sh"

EXPORT="$SPIKE_ROOT/export"          # bound rshared into the container
MNT="$EXPORT/secrets"                # served subpath, one level down
BACKING="$SPIKE_ROOT/backing"        # OUTSIDE the export dir

build
rm -rf "$EXPORT"; mkdir -p "$EXPORT" "$MNT"
seed  # writes to $BACKING (outside EXPORT)

echo "== export dir contents (must be only the mountpoint, no backing) =="
ls -la "$EXPORT"

# Make the export dir a shared mount point so a new FUSE mount propagates.
${SUDO:-} mount --bind "$EXPORT" "$EXPORT"; ${SUDO:-} mount --make-rshared "$EXPORT"

unmount_stale
"$BIN" -backing "$BACKING" -mount "$MNT" -log "$LOG" -allow-other -hash-exe > "$SPIKE_ROOT/daemon.out" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 50); do mountpoint -q "$MNT" && break; sleep 0.1; done
mountpoint "$MNT"; echo "daemon pid $DAEMON_PID"

CID=$(docker run -d --rm --user "$(id -u):$(id -g)" -v "$EXPORT:/export:rshared" "$IMAGE" sleep 600)
echo "== container view: /export must show only 'secrets', never 'backing' =="
docker exec "$CID" ls -la /export
echo "== container read through FUSE (redacted for cat) =="
docker exec "$CID" cat /export/secrets/gh/hosts.yml
echo "== direct-backing probe: no path under /export reaches real bytes =="
docker exec "$CID" sh -c 'ls -la /export/backing 2>&1; cat /export/backing/gh/hosts.yml 2>&1' || true
docker exec "$CID" sh -c 'find /export -name hosts.yml -exec grep -l gho_FAKE {} + 2>&1' || echo "no real token reachable under /export"

echo "== daemon-down window under the export topology =="
kill "$DAEMON_PID" 2>/dev/null; sleep 1
echo "-- container read while daemon down (must fail closed, not expose backing) --"
docker exec "$CID" sh -c 'cat /export/secrets/gh/hosts.yml 2>&1' || true
docker exec "$CID" sh -c 'ls /export/secrets 2>&1' || true

echo "== gap probe: after clearing the dead mount, before remount =="
# Round-2 review: prove the exposed interval does not reveal backing. The
# mountpoint is now an empty real directory under the export; it must NOT
# contain the credential (backing lives outside the export).
unmount_stale
echo "-- host view of the bare mountpoint during the gap --"
ls -la "$MNT" 2>&1
echo "-- container view during the gap (empty dir or ENOTCONN, never real bytes) --"
docker exec "$CID" sh -c 'ls -la /export/secrets 2>&1; cat /export/secrets/gh/hosts.yml 2>&1' || true

echo "== remount into the running container (B2 recovery) =="
# The new mount then propagates in.
"$BIN" -backing "$BACKING" -mount "$MNT" -log "$LOG" -allow-other -hash-exe > "$SPIKE_ROOT/daemon.out" 2>&1 &
for _ in $(seq 1 50); do mountpoint -q "$MNT" && break; sleep 0.1; done
docker exec "$CID" sh -c 'cat /export/secrets/gh/hosts.yml 2>&1' || true

docker rm -f "$CID" >/dev/null 2>&1 || true
stop_daemon
${SUDO:-} umount -l "$EXPORT" 2>/dev/null || true
