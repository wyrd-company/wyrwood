#!/usr/bin/env bash
# Shared setup for the task 847 spike experiments. Source this file.
set -u
SPIKE_ROOT="${SPIKE_ROOT:-$HOME/Code/spikes/847}"
BACKING="$SPIKE_ROOT/backing"
MNT="$SPIKE_ROOT/mnt"
LOG="$SPIKE_ROOT/identity.log"
BIN="$SPIKE_ROOT/secretfs"
IMAGE="${IMAGE:-ubuntu:24.04}"

build() {
  (cd "$(dirname "${BASH_SOURCE[0]}")/../secretfs" && CGO_ENABLED=0 go build -o "$BIN" .) || exit 1
}

seed() {
  mkdir -p "$BACKING/gh" "$BACKING/codex" "$MNT"
  cat > "$BACKING/gh/hosts.yml" <<'Y'
github.com:
    users:
        example-user:
            oauth_token: gho_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
    oauth_token: gho_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE
    user: example-user
    git_protocol: ssh
Y
  cat > "$BACKING/codex/auth.json" <<'J'
{"OPENAI_API_KEY": "sk-FAKEFAKEFAKEFAKEFAKEFAKE", "tokens": {"access_token": "eyFAKE.FAKE.FAKE", "refresh_token": "rt_FAKE"}}
J
}

# start_daemon [extra flags...]
unmount_stale() {
  # mountpoint -q fails on a dead FUSE mount, so unmount unconditionally.
  fusermount3 -uz "$MNT" 2>/dev/null || true
}

start_daemon() {
  unmount_stale
  "$BIN" -backing "$BACKING" -mount "$MNT" -log "$LOG" -allow-other "$@" > "$SPIKE_ROOT/daemon.out" 2>&1 &
  DAEMON_PID=$!
  for _ in $(seq 1 50); do mountpoint -q "$MNT" && break; sleep 0.1; done
  mountpoint "$MNT"; echo "daemon pid $DAEMON_PID"
}

stop_daemon() {
  for p in /proc/[0-9]*; do
    [ "$(readlink "$p/exe" 2>/dev/null)" = "$BIN" ] && kill "${p#/proc/}" 2>/dev/null
  done
  sleep 0.5
  unmount_stale
}

tail_log() { tail -n "${1:-5}" "$LOG"; }
