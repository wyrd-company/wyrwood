#!/usr/bin/env bash
# Q4: allowlisted temp-file-and-rename writes land; redacted readers see the new file; non-allowlisted writes denied.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
say() { printf '\n### %s\n' "$*"; }
build; seed; stop_daemon; : > "$LOG"
(cd "$(dirname "${BASH_SOURCE[0]}")/../tools/tmpwriter" && CGO_ENABLED=0 go build -o "$SPIKE_ROOT/tmpwriter" .) || exit 1

# Image with gh installed (native Go binary) and our tmpwriter copied in.
TMPD=$(mktemp -d); cp "$SPIKE_ROOT/tmpwriter" "$TMPD/"
cat > "$TMPD/Dockerfile" <<D
FROM $IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends gh ca-certificates && rm -rf /var/lib/apt/lists/*
COPY tmpwriter /usr/local/bin/tmpwriter
RUN cp /usr/local/bin/tmpwriter /usr/local/bin/tmpwriter-copy
D
docker build -q -t spike847-gh "$TMPD" >/dev/null || exit 1
GH_EXE=$(docker run --rm spike847-gh readlink -f "$(docker run --rm spike847-gh which gh)")
echo "gh exe inside container: $GH_EXE"

start_daemon -allow "/usr/local/bin/tmpwriter,$GH_EXE"
docker rm -f spike847 >/dev/null 2>&1 || true
docker run -d --rm --name spike847 -u 1000:1000 -e GH_CONFIG_DIR=/secrets/gh -e HOME=/tmp \
  --mount "type=bind,src=$MNT,dst=/secrets" spike847-gh sleep 600 >/dev/null

say "allowlisted tmpwriter: temp+rename over hosts.yml"
docker exec spike847 tmpwriter /secrets/gh/hosts.yml 'github.com:
    oauth_token: gho_NEWFAKE_NEWFAKE_NEWFAKE
    user: example-user'
tail_log 3
say "backing file on host after rename"; cat "$BACKING/gh/hosts.yml"
say "redacted reader (cat, not allowlisted) sees the new file"; docker exec spike847 cat /secrets/gh/hosts.yml
say "non-allowlisted writer (identical binary, different path) denied"
docker exec spike847 tmpwriter-copy /secrets/gh/hosts.yml 'github.com:
    oauth_token: gho_ATTACKER'; tail_log 2
say "backing file unchanged?"; grep -c ATTACKER "$BACKING/gh/hosts.yml"
say "non-allowlisted unlink denied"; docker exec spike847 rm /secrets/gh/hosts.yml; ls "$BACKING/gh"

say "gh (allowlisted) reads real token: gh auth status"
docker exec spike847 gh auth status 2>&1 | head -5; tail_log 2
say "gh writes: gh auth logout"
docker exec spike847 gh auth logout --hostname github.com --user example-user 2>&1 | head -3; tail_log 4
say "backing hosts.yml after logout"; cat "$BACKING/gh/hosts.yml" 2>&1; ls -la "$BACKING/gh"
say "gh writes: gh auth login --with-token (fake token, expect API validation failure; does it write?)"
docker exec -i spike847 gh auth login --hostname github.com --with-token <<< "gho_FAKELOGIN" 2>&1 | head -3; tail_log 3
say "backing hosts.yml after login attempt"; cat "$BACKING/gh/hosts.yml" 2>&1
say "gh writes: gh config set (config.yml)"
docker exec spike847 gh config set git_protocol https 2>&1 | head -2; tail_log 3; cat "$BACKING/gh/config.yml" 2>&1
say "identity log for gh ops"; grep -E '"(create|rename|unlink|setattr)' "$LOG" | tail -8
docker rm -f spike847 >/dev/null 2>&1 || true
stop_daemon
