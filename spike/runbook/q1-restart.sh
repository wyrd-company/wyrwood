#!/usr/bin/env bash
# Q1: does a running container survive a daemon restart under its bind mount?
# Usage: q1-restart.sh   (run on the host; needs docker, fusermount3, go)
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
build; seed; stop_daemon; : > "$LOG"
say() { printf '\n### %s\n' "$*"; }

run_case() {
  local label="$1"; shift
  local propagation="$1"; shift
  say "CASE $label (mount propagation: $propagation)"
  start_daemon "$@"
  docker rm -f spike847 >/dev/null 2>&1 || true
  docker run -d --rm --name spike847 -u 1000:1000 \
    --mount "type=bind,src=$MNT/gh,dst=/secrets/gh,bind-propagation=$propagation" \
    "$IMAGE" sleep 600 >/dev/null
  echo "-- before restart:"; docker exec spike847 cat /secrets/gh/hosts.yml | head -3
  echo "-- findmnt inside container:"; docker exec spike847 cat /proc/self/mountinfo | grep secrets
}

# Case A: plain kill + remount (the naive restart).
run_case A rprivate
kill "$DAEMON_PID"; sleep 0.5; mountpoint "$MNT" || echo "host mountpoint gone"
echo "-- after kill, before remount:"; docker exec spike847 cat /secrets/gh/hosts.yml 2>&1 | head -3
start_daemon
echo "-- after remount (rprivate):"; docker exec spike847 cat /secrets/gh/hosts.yml 2>&1 | head -3
docker rm -f spike847 >/dev/null

# Case B: shared propagation on the container bind mount.
stop_daemon
run_case B rshared
kill "$DAEMON_PID"; sleep 0.5
echo "-- after kill:"; docker exec spike847 cat /secrets/gh/hosts.yml 2>&1 | head -3
start_daemon
echo "-- after remount (rshared):"; docker exec spike847 cat /secrets/gh/hosts.yml 2>&1 | head -3
echo "-- container mountinfo now:"; docker exec spike847 cat /proc/self/mountinfo | grep secrets
docker rm -f spike847 >/dev/null

# Case C: fd handoff. The daemon re-execs itself on SIGUSR1 passing the /dev/fuse fd.
stop_daemon
run_case C rprivate -reexec-on-usr1
OLD=$DAEMON_PID
kill -USR1 "$OLD"; sleep 1
echo "-- daemon processes now:"; pgrep -af "$BIN"; echo "old pid $OLD alive? $(kill -0 $OLD 2>/dev/null && echo yes || echo no)"
echo "-- after fd handoff:"; docker exec spike847 cat /secrets/gh/hosts.yml 2>&1 | head -3
echo "-- host read after handoff:"; head -3 "$MNT/gh/hosts.yml"
docker rm -f spike847 >/dev/null
echo "-- daemon.out:"; cat "$SPIKE_ROOT/daemon.out"
stop_daemon
