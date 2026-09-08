#!/usr/bin/env bash
# Q5: with the daemon down, how does each CLI behave? Two down-states:
#  (a) daemon killed without unmount: reads fail ENOTCONN
#  (b) cleanly unmounted: container sees the underlying empty dir (bind of mountpoint dir)
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
say() { printf '\n### %s\n' "$*"; }
build; seed; stop_daemon; : > "$LOG"

TMPD=$(mktemp -d)
cat > "$TMPD/Dockerfile" <<D
FROM node:24-slim
RUN apt-get update && apt-get install -y --no-install-recommends gh ca-certificates curl && rm -rf /var/lib/apt/lists/* \
 && npm install -g @openai/codex @anthropic-ai/claude-code 2>&1 | tail -2
D
docker build -q -t spike847-clis "$TMPD" >/dev/null || exit 1

start_daemon
mkdir -p "$BACKING/claude" "$BACKING/npm"
echo '{"claudeAiOauth":{"accessToken":"sk-ant-FAKE","refreshToken":"sk-ant-rFAKE","expiresAt":9999999999999}}' > "$BACKING/claude/.credentials.json"
echo '//registry.npmjs.org/:_authToken=npm_FAKE' > "$BACKING/npm/.npmrc"
docker rm -f spike847 >/dev/null 2>&1 || true
docker run -d --rm --name spike847 -u 1000:1000 -e HOME=/home/u -e GH_CONFIG_DIR=/home/u/.config/gh -e CODEX_HOME=/home/u/.codex \
  --mount "type=bind,src=$MNT/gh,dst=/home/u/.config/gh" \
  --mount "type=bind,src=$MNT/codex,dst=/home/u/.codex" \
  --mount "type=bind,src=$MNT/claude,dst=/home/u/.claude" \
  --mount "type=bind,src=$MNT/npm/.npmrc,dst=/home/u/.npmrc" \
  spike847-clis sleep 900 >/dev/null
docker exec -u 0 spike847 sh -c 'mkdir -p /home/u && chown 1000:1000 /home/u'

probe() {
  say "gh auth status"; docker exec spike847 gh auth status 2>&1 | head -4; echo "exit=${PIPESTATUS[0]}"
  say "codex login status"; docker exec spike847 timeout 20 codex login status 2>&1 | head -4; echo "exit=${PIPESTATUS[0]}"
  say "claude auth status (non-interactive)"; docker exec spike847 timeout 20 claude auth status 2>&1 | head -4; echo "exit=${PIPESTATUS[0]}"
  say "npm config get authToken"; docker exec spike847 npm config get //registry.npmjs.org/:_authToken 2>&1 | head -3; echo "exit=${PIPESTATUS[0]}"
  say "files as the container sees them"; docker exec spike847 sh -c 'ls -la /home/u/.config/gh /home/u/.codex /home/u/.claude; cat /home/u/.npmrc' 2>&1 | head -20
}

say "=== STATE: daemon up (baseline; readers not allowlisted so they see redacted values) ==="
probe
say "=== STATE: daemon killed, mount left dangling ==="
kill -9 "$DAEMON_PID"; sleep 0.5; mountpoint "$MNT" 2>&1; ls "$MNT" 2>&1
probe
say "=== does a login attempt overwrite? gh auth login --with-token while dangling ==="
docker exec -i spike847 gh auth login --hostname github.com --with-token <<< "gho_FAKE2" 2>&1 | head -3
say "=== STATE: cleanly unmounted (container bind now points at the empty mountpoint dir) ==="
fusermount3 -uz "$MNT" 2>&1; ls -la "$MNT" 2>&1
probe
say "=== does a login attempt overwrite/create? gh auth login --with-token while unmounted ==="
docker exec -i spike847 gh auth login --hostname github.com --with-token <<< "gho_FAKE2" 2>&1 | head -3
docker exec spike847 ls -la /home/u/.config/gh 2>&1; ls -la "$MNT/gh" 2>&1
say "=== STATE: daemon restarted (new mount on host); what does the running container see? ==="
start_daemon
probe
docker rm -f spike847 >/dev/null 2>&1 || true
stop_daemon
rm -rf "$MNT/gh" 2>/dev/null; true
