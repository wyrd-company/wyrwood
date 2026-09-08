#!/usr/bin/env bash
# Q2/Q3: what identity does the daemon see for container requesters?
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
build; seed; stop_daemon; : > "$LOG"
say() { printf '\n### %s\n' "$*"; }

start_daemon -hash-exe
docker rm -f spike847 >/dev/null 2>&1 || true
docker run -d --rm --name spike847 -u 1000:1000 \
  --mount "type=bind,src=$MNT,dst=/secrets" "$IMAGE" sleep 600 >/dev/null

say "host reader"; head -2 "$MNT/gh/hosts.yml"; tail_log 1
say "container cat (redacted expected)"; docker exec spike847 cat /secrets/gh/hosts.yml; tail_log 1
say "container cp of /bin/cat to /tmp/cat2, then read"; docker exec spike847 sh -c 'cp /bin/cat /tmp/cat2 && /tmp/cat2 /secrets/codex/auth.json'; tail_log 1
say "container: sh -c with exec (identity of the reading process)"; docker exec spike847 sh -c 'exec head -1 /secrets/gh/hosts.yml'; tail_log 1
say "container: shell builtin read (identity is the shell)"; docker exec spike847 sh -c 'read -r l < /secrets/gh/hosts.yml; echo "$l"'; tail_log 1
say "container: write attempt (denied expected)"; docker exec spike847 sh -c 'echo x >> /secrets/gh/hosts.yml; echo exit=$?'; tail_log 1
say "container: pid namespace and exe for a reader"; docker exec spike847 sh -c 'readlink /proc/self/ns/pid; readlink /proc/self/ns/mnt; readlink /proc/self/exe'
say "host view of the same: what /proc/<pid>/exe resolved to in the log"; grep '"container"' "$LOG" | tail -3
say "container root (uid 0) reader"; docker exec -u 0 spike847 cat /secrets/gh/hosts.yml 2>&1 | head -2; tail_log 1

say "allowlist by exe path: restart with /usr/bin/cat allowed"
stop_daemon; start_daemon -hash-exe -allow /usr/bin/cat
docker rm -f spike847 >/dev/null 2>&1 || true
docker run -d --rm --name spike847 -u 1000:1000 --mount "type=bind,src=$MNT,dst=/secrets" "$IMAGE" sleep 600 >/dev/null
say "container cat (real expected)"; docker exec spike847 cat /secrets/gh/hosts.yml | head -2; tail_log 1
say "container /tmp/cat2 copy (redacted expected: path differs)"; docker exec spike847 sh -c 'cp /bin/cat /tmp/cat2 && /tmp/cat2 /secrets/gh/hosts.yml | head -2'; tail_log 1
say "spoof: bind-mount a different binary over /usr/bin/cat inside the container (needs root in container)"
docker exec -u 0 spike847 sh -c 'cp /bin/head /tmp/fakecat && mount --bind /tmp/fakecat /usr/bin/cat 2>&1; cat -n 1 /secrets/gh/hosts.yml 2>&1 | head -2' ; tail_log 1
say "spoof: attacker-built image where /usr/bin/cat is a different binary"
docker rm -f spike847 >/dev/null 2>&1 || true
TMPD=$(mktemp -d); printf 'FROM %s\nRUN cp /bin/head /usr/bin/cat\n' "$IMAGE" > "$TMPD/Dockerfile"
docker build -q -t spike847-spoof "$TMPD" >/dev/null
docker run --rm -u 1000:1000 --mount "type=bind,src=$MNT,dst=/secrets" spike847-spoof cat -n 2 /secrets/gh/hosts.yml; tail_log 1
say "exe dev/ino and sha256 for genuine vs spoofed cat from the log"; grep '"container"' "$LOG" | grep -o '"exe":"[^"]*","exe_dev":[0-9]*,"exe_ino":[0-9]*,"exe_sha256":"[0-9a-f]*"' | sort | uniq -c

say "Q3 interpreted CLI: node reader"
docker run --rm -u 1000:1000 --mount "type=bind,src=$MNT,dst=/secrets" node:24-slim node -e 'console.log(require("fs").readFileSync("/secrets/gh/hosts.yml","utf8").split("\n")[3])'; tail_log 1
say "Q3: node with a spoofed script name and argv0"
docker run --rm -u 1000:1000 --mount "type=bind,src=$MNT,dst=/secrets" node:24-slim bash -c 'printf "console.log(require(\"fs\").readFileSync(\"/secrets/gh/hosts.yml\",\"utf8\").split(\"\\n\")[3])" > /tmp/gh; exec -a /usr/local/bin/gh node /tmp/gh'; tail_log 1
say "Q3: what the daemon logged for the node readers"; grep node "$LOG" | tail -2
docker rm -f spike847 >/dev/null 2>&1 || true
stop_daemon
