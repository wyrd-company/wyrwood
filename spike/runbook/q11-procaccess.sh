#!/usr/bin/env bash
# Finding 3 + 6: process access paths left untested in round 1, and the
# now-guarded loopback mutations.
#
# 3a. same-UID non-descendant: PTRACE_ATTACH, /proc/pid/mem, environ, fd
#     (ptracetest now tests environ and fd INDEPENDENTLY of the mem outcome).
# 3b. parent-child (ancestor) tracing under Yama scope 1: an attacker that
#     LAUNCHES the allowlisted CLI as its own child (ancestorptrace).
# 3c. /proc/pid/fd as root in the container.
# 6.  Symlink/Link/Rmdir/Mknod/Setxattr from a non-allowlisted writer are now
#     denied by the gate (round 1 left them unguarded).
set -u
. "$(dirname "$0")/common.sh"

TOOLS="$(cd "$(dirname "$0")/../tools" && pwd)"
build
(cd "$TOOLS/ptracetest" && CGO_ENABLED=0 go build -o "$SPIKE_ROOT/ptracetest" .) || exit 1
(cd "$TOOLS/ancestorptrace" && CGO_ENABLED=0 go build -o "$SPIKE_ROOT/ancestorptrace" .) || exit 1
(cd "$TOOLS/credchild" && CGO_ENABLED=0 go build -o "$SPIKE_ROOT/credchild" .) || exit 1

rm -rf "$BACKING" "$MNT"; mkdir -p "$MNT"; seed
CHILDHASH=$(sha256sum "$SPIKE_ROOT/credchild" | awk '{print $1}')
unmount_stale
"$BIN" -backing "$BACKING" -mount "$MNT" -log "$LOG" -allow-other -hash-exe -allow-sha256 "$CHILDHASH" > "$SPIKE_ROOT/daemon.out" 2>&1 &
for _ in $(seq 1 50); do mountpoint -q "$MNT" && break; sleep 0.1; done
mountpoint "$MNT"

CID=$(docker run -d --rm --user "$(id -u):$(id -g)" \
  -v "$MNT:/secrets:${PROP:-rshared}" \
  -v "$SPIKE_ROOT/ptracetest:/usr/local/bin/ptracetest:ro" \
  -v "$SPIKE_ROOT/ancestorptrace:/usr/local/bin/ancestorptrace:ro" \
  -v "$SPIKE_ROOT/credchild:/usr/local/bin/credchild:ro" \
  "$IMAGE" sleep 400)

echo "== 3a. same-UID non-descendant (victim holds a secret in env) =="
docker exec -d "$CID" sh -c 'SECRET_IN_ENV=canary-1234 exec sleep 300'
VPID=$(docker exec "$CID" sh -c 'pgrep -f "SECRET_IN_ENV|sleep 300" | head -1')
docker exec "$CID" sh -c "ptracetest ${VPID:-1}" || true

echo "== 3b. ancestor recovers the REAL credential from an allowlisted reader =="
# ancestorptrace launches credchild (allowlisted by hash), which loads the real
# gho_ token into memory; the ancestor scans the child memory for it.
docker exec -e NEEDLE=gho_FAKE "$CID" ancestorptrace credchild /secrets/gh/hosts.yml || true

echo "== 3d. same-UID non-descendant via /proc/<pid>/fd re-opens through FUSE =="
# credchild holds an open fd to the credential; a same-UID attacker opening
# /proc/<pid>/fd/N re-enters FUSE as ITSELF (non-allowlisted) -> must be redacted.
docker exec -d "$CID" sh -c 'exec credchild /secrets/gh/hosts.yml'
sleep 1
CHPID=$(docker exec "$CID" pgrep -n -x credchild)
docker exec "$CID" sh -c 'for fd in /proc/'"${CHPID:-1}"'/fd/*; do t=$(readlink "$fd" 2>/dev/null); case "$t" in *hosts.yml*) echo "reading $fd -> $t"; cat "$fd" 2>&1; ;; esac; done' || true

echo "== 3c. /proc/pid/fd as root in the container =="
docker exec -u 0 "$CID" sh -c "ls -la /proc/${VPID:-1}/fd 2>&1 | head" || true

echo "== 6. loopback mutations from a non-allowlisted writer (expect EACCES) =="
docker exec "$CID" sh -c '
  cd /secrets/gh
  echo "-- hardlink --";   ln    hosts.yml stolen.hardlink 2>&1
  echo "-- symlink --";    ln -s hosts.yml stolen.symlink  2>&1
  echo "-- rmdir --";      rmdir /secrets/codex            2>&1
  echo "-- mknod fifo (no priv needed; must hit the gate) --"; mknod /secrets/gh/fifo p 2>&1
  echo "-- setxattr --";   command -v setfattr >/dev/null && setfattr -n user.x -v y hosts.yml 2>&1 || echo "setfattr not installed"
'
echo "-- backing dir must show none of those artifacts --"
ls -la "$BACKING/gh"

docker rm -f "$CID" >/dev/null 2>&1 || true
stop_daemon
