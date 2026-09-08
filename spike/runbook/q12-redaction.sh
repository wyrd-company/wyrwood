#!/usr/bin/env bash
# Round 3, finding 1: redaction fails closed on the vectors round 2 leaked.
# Seeds CRLF PEM, truncated PEM, and a YAML block-scalar token, plus the good
# gh/codex files, then a NON-allowlisted reader cats each. No canary may survive.
set -u
. "$(dirname "$0")/common.sh"

build
rm -rf "$BACKING" "$MNT"; mkdir -p "$BACKING/gh" "$BACKING/codex" "$BACKING/keys" "$MNT"

printf -- '-----BEGIN RSA PRIVATE KEY-----\r\nMIICANARYcrlfKEYMATERIALaaaabbbbccccddddeeee\r\n-----END RSA PRIVATE KEY-----\r\n' > "$BACKING/keys/crlf.pem"
printf -- '-----BEGIN RSA PRIVATE KEY-----\nMIICANARYtruncKEYMATERIALaaaabbbbccccddddeeee\n' > "$BACKING/keys/trunc.pem"
cat > "$BACKING/gh/hosts.yml" <<'Y'
github.com:
    oauth_token: |
        gho_CANARYblockScalarAAAABBBBCCCCDDDDEEEE
    user: example-user
    git_protocol: ssh
Y
cat > "$BACKING/codex/auth.json" <<'J'
{"OPENAI_API_KEY":"sk-CANARYaaaabbbbccccddddeeee","tokens":{"access_token":"eyCANARYaccessAAAABBBBCCCC","refresh_token":"rtCANARYrefreshAAAABBBBCCCC"}}
J

start_daemon -hash-exe   # no allowlist -> every container reader is redacted
CID=$(docker run -d --rm --user "$(id -u):$(id -g)" -v "$MNT:/secrets:${PROP:-rshared}" "$IMAGE" sleep 300)

fail=0
check_no_canary() {
  local f="$1"; shift
  echo "== $f =="
  out=$(docker exec "$CID" cat "$f")
  echo "$out"
  for c in "$@"; do
    if printf '%s' "$out" | grep -q "$c"; then echo "LEAK: $c survived in $f"; fail=1; fi
  done
}
check_no_canary /secrets/keys/crlf.pem  CANARYcrlf
check_no_canary /secrets/keys/trunc.pem CANARYtrunc
check_no_canary /secrets/gh/hosts.yml   CANARYblockScalar
check_no_canary /secrets/codex/auth.json CANARYaccess CANARYrefresh sk-CANARY
echo "-- good gh file must still expose non-secret structure to an allowlisted reader --"
docker rm -f "$CID" >/dev/null 2>&1; stop_daemon
CATHASH=$(docker run --rm "$IMAGE" sha256sum /bin/cat | awk '{print $1}')
start_daemon -hash-exe -allow-sha256 "$CATHASH"
CID=$(docker run -d --rm --user "$(id -u):$(id -g)" -v "$MNT:/secrets:${PROP:-rshared}" "$IMAGE" sleep 300)
docker exec "$CID" cat /secrets/gh/hosts.yml
docker rm -f "$CID" >/dev/null 2>&1; stop_daemon

echo "RESULT: $([ $fail -eq 0 ] && echo 'no canaries survived (fail-closed)' || echo 'LEAKS FOUND')"
