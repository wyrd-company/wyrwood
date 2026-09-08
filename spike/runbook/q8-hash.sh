#!/usr/bin/env bash
# Finding 8: hash enforcement as the deciding factor, with the per-(mnt-ns,
# dev, inode, mtime) cache. Round 1 used path allowlists; -allow-sha256 was
# logged but never decided. Here we allow ONLY by hash (no -allow path), then:
#   1. an allowlisted binary reads real bytes;
#   2. a byte-identical copy at a different path also reads real (hash, not path);
#   3. a different binary (spoof) is redacted;
#   4. replacing the allowlisted file's bytes (same path) flips it to redacted;
#   5. the cache records hits after the first hash of a stable (dev,ino,mtime).
set -u
. "$(dirname "$0")/common.sh"

build
rm -rf "$BACKING" "$MNT"; mkdir -p "$MNT"; seed

# Compute the container-side hash of the reader we will allow. Use /bin/cat
# from the target image; hash it as the daemon would see it (its own bytes).
CATHASH=$(docker run --rm "$IMAGE" sha256sum /bin/cat | awk '{print $1}')
echo "allowlisted sha256 = $CATHASH"

unmount_stale
"$BIN" -backing "$BACKING" -mount "$MNT" -log "$LOG" -allow-other -hash-exe \
  -allow-sha256 "$CATHASH" > "$SPIKE_ROOT/daemon.out" 2>&1 &
for _ in $(seq 1 50); do mountpoint -q "$MNT" && break; sleep 0.1; done
mountpoint "$MNT"

CID=$(docker run -d --rm -v "$MNT:/secrets:rshared" "$IMAGE" sleep 600)

echo "== 1. allowlisted /bin/cat: expect real token =="
docker exec "$CID" cat /secrets/gh/hosts.yml
echo "== 2. identical copy at /tmp/cat2: expect real (hash matches) =="
docker exec "$CID" sh -c 'cp /bin/cat /tmp/cat2 && /tmp/cat2 /secrets/gh/hosts.yml'
echo "== 3. different binary (head copied over a path): expect REDACTED =="
docker exec "$CID" sh -c 'cp /usr/bin/head /tmp/notcat && /tmp/notcat /secrets/gh/hosts.yml'
echo "== 4. replace allowlisted bytes at same path: expect REDACTED (hash changed) =="
docker exec "$CID" sh -c 'cp /usr/bin/head /bin/cat && cat /secrets/gh/hosts.yml' || true

echo "== 5. cache behaviour: repeated reads by the same stable binary =="
docker exec "$CID" sh -c 'cp /tmp/cat2 /tmp/cat3; for i in 1 2 3; do /tmp/cat3 /secrets/gh/hosts.yml >/dev/null; done; echo done'
echo "-- daemon reports hits/misses on exit (SIGUSR2 dump not wired; grep log) --"
grep -c '"exe_sha256"' "$LOG" || true

docker rm -f "$CID" >/dev/null 2>&1 || true
# Dump the hash cache counters before killing the daemon.
for pp in /proc/[0-9]*; do [ "$(readlink "$pp/exe" 2>/dev/null)" = "$BIN" ] && kill -USR2 "${pp#/proc/}"; done
sleep 0.3
echo "== cache counters (hits should be > 0 after step 5) =="
grep -i hashcache "$SPIKE_ROOT/daemon.out" || echo "(no cache line)"
stop_daemon
