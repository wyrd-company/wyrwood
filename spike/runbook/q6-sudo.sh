#!/usr/bin/env bash
# Q6: same-UID ptrace under Docker default seccomp/caps + Yama, and sudo revocation.
# Part A runs in a plain container; Part B (real devcontainer) is a manual step, see README.
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"
say() { printf '\n### %s\n' "$*"; }
(cd "$(dirname "${BASH_SOURCE[0]}")/../tools/ptracetest" && CGO_ENABLED=0 go build -o "$SPIKE_ROOT/ptracetest" .) || exit 1
TMPD=$(mktemp -d); cp "$SPIKE_ROOT/ptracetest" "$TMPD/"
cat > "$TMPD/Dockerfile" <<D
FROM $IMAGE
RUN apt-get update && apt-get install -y --no-install-recommends sudo && rm -rf /var/lib/apt/lists/* \
 && useradd -m -u 1000 -s /bin/bash vscode && echo 'vscode ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/vscode && chmod 0440 /etc/sudoers.d/vscode
COPY ptracetest /usr/local/bin/ptracetest
D
docker build -q -t spike847-ptrace "$TMPD" >/dev/null || exit 1
docker rm -f spike847 >/dev/null 2>&1 || true
docker run -d --rm --name spike847 -u vscode spike847-ptrace sleep 900 >/dev/null
say "yama inside container"; docker exec spike847 cat /proc/sys/kernel/yama/ptrace_scope
say "capabilities of container user"; docker exec spike847 grep Cap /proc/self/status
TARGET=$(docker exec -d spike847 sleep 800; docker exec spike847 pgrep -n -x sleep)
say "same-uid non-descendant ptrace (default profile), target pid $TARGET"; docker exec spike847 ptracetest "$TARGET"
say "with sudo still present: sudo cat /proc/pid/environ"; docker exec spike847 sudo head -c 40 /proc/$TARGET/environ; echo
say "revoke sudo"; docker exec -u 0 spike847 rm /etc/sudoers.d/vscode
docker exec spike847 sudo -n true 2>&1 | head -1
say "same-uid ptrace after sudo removal"; docker exec spike847 ptracetest "$TARGET"
say "with --cap-add SYS_PTRACE (what a devcontainer.json capAdd would grant)"
docker run --rm -u vscode --cap-add SYS_PTRACE spike847-ptrace sh -c 'sleep 100 & sleep 0.2; ptracetest $!'
say "with ptrace_scope=0 semantics: not testable without host change; recorded as-is"
docker rm -f spike847 >/dev/null 2>&1 || true
