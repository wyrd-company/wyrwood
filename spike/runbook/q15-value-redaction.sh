#!/usr/bin/env bash
# Round 4: value-based redaction. Wyrwood is told the exact secret VALUES (a
# secrets-file) and redacts them wherever they appear, format-agnostic. This
# fails closed for known secrets regardless of key name, length, or file shape
# -- including the short-secret and block-scalar vectors the round-3 review
# broke, and a value that appears in an UNMODELED file the structural pass would
# pass through.
set -u
. "$(dirname "$0")/common.sh"

build
rm -rf "$BACKING" "$MNT"; mkdir -p "$BACKING/gh" "$BACKING/misc" "$MNT"

# Known secret values (as if registered by the tools that wrote them).
SHORT="pin4931"
GHO="gho_VALUEredactAAAABBBBCCCCDDDD"
printf '%s\n%s\n' "$GHO" "$SHORT" > "$SPIKE_ROOT/secrets.txt"

# The same short PIN appears (a) under an unmodeled JSON key and (b) in a
# freeform log file with no key/value structure at all.
cat > "$BACKING/gh/hosts.yml" <<Y
github.com:
    oauth_token: $GHO
    user: example-user
Y
printf '{"weird_unmodeled_key":"%s"}\n' "$SHORT" > "$BACKING/misc/state.json"
printf 'session opened; pin was %s; closing\n' "$SHORT" > "$BACKING/misc/audit.log"

start_daemon -hash-exe -secrets-file "$SPIKE_ROOT/secrets.txt"
CID=$(docker run -d --rm --user "$(id -u):$(id -g)" -v "$MNT:/secrets:${PROP:-rshared}" "$IMAGE" sleep 200)

fail=0
probe(){ echo "== $1 =="; out=$(docker exec "$CID" cat "$1"); echo "$out"; shift; for c in "$@"; do printf '%s' "$out" | grep -q "$c" && { echo "LEAK: $c"; fail=1; }; done; }
probe /secrets/gh/hosts.yml       "$GHO"
probe /secrets/misc/state.json    "$SHORT"
probe /secrets/misc/audit.log     "$SHORT"

docker rm -f "$CID" >/dev/null 2>&1; stop_daemon
echo "RESULT: $([ $fail -eq 0 ] && echo 'all known secret values redacted across every format' || echo 'LEAKS FOUND')"
echo "NOTE: redacted output is served ONLY to non-allowlisted readers and is not"
echo "      guaranteed valid/complete; allowlisted readers get the real bytes."
