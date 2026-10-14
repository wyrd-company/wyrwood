#!/usr/bin/env bash
# ---
# relationships:
#   demonstrates: overview
#   references:
#     - controller
#     - agent
#     - web-interface
# ---
#
# Runs a throwaway Wyrwood site for the recorded demos: an OpenBao dev
# server and a mock OpenID Connect provider in containers, a controller and
# an agent on this host, and a separate Docker Engine holding only the
# workload containers the agent reports.
#
#   docs/demo/stack.sh up      start everything and log the agent in (pending)
#   docs/demo/stack.sh agent   start the agent daemon once its key is approved
#   docs/demo/stack.sh down    stop everything and remove all demo state
#
# Requires Docker Engine on this host, sudo, Go, curl, and jq. The agent runs
# as root with its default paths. up refuses to start when any of those paths
# exists, and down removes them only when this demo created them.
set -euo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
root=${WYRWOOD_DEMO_ROOT:-/tmp/wyrwood-demo}
bao_port=18200
oidc_port=18090
http_port=18088
ssh_port=12222
workload_image=wyrwood-demo-workload:local
root_token=wyrwood-demo-root
engine=$root/engine
agent_paths=(/etc/wyrwood /var/lib/wyrwood /run/wyrwood)
# up records that it created the agent paths, so down never removes the
# state of an agent this demo did not configure.
owned=$root/agent-paths-owned

engine_docker() {
	sudo docker -H "unix://$engine/docker.sock" "$@"
}

bao() {
	docker exec -i -e BAO_ADDR=http://127.0.0.1:8200 -e BAO_TOKEN="$root_token" wyrwood-demo-bao bao "$@"
}

wait_for() {
	local what=$1
	shift
	for _ in $(seq 1 150); do
		if "$@" >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.2
	done
	echo "timed out waiting for $what" >&2
	return 1
}

# demo_owns_agent_paths reports whether up created the agent paths and the
# agent configuration still names the demo controller.
demo_owns_agent_paths() {
	[ -f "$owned" ] && ! sudo test -L /etc/wyrwood/agent.yml &&
		sudo grep -qE "^[[:space:]]+url: ssh://127\.0\.0\.1:$ssh_port\$" /etc/wyrwood/agent.yml 2>/dev/null
}

up() {
	for path in "${agent_paths[@]}"; do
		if sudo test -e "$path"; then
			echo "$path exists: this host has Wyrwood agent state; the demo will not touch it" >&2
			exit 1
		fi
	done
	mkdir -p "$root/bin" "$root/controller"
	: >"$owned"
	(cd "$repository" && go build -o "$root/bin/wyrwood" ./cmd/wyrwood)
	docker build --quiet --tag "$workload_image" "$repository/internal/integration/testdata" >/dev/null

	docker run -d --name wyrwood-demo-bao -p "127.0.0.1:$bao_port:8200" \
		-e BAO_DEV_ROOT_TOKEN_ID="$root_token" -e BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200 \
		openbao/openbao:2.4.1 >/dev/null
	wait_for "OpenBao" curl -fsS "http://127.0.0.1:$bao_port/v1/sys/health"
	bao auth enable approle >/dev/null
	bao secrets enable -version=2 kv >/dev/null
	bao secrets enable transit >/dev/null
	bao secrets enable ssh >/dev/null
	bao write ssh/config/ca generate_signing_key=true key_type=ed25519 >/dev/null
	bao policy write wyrwood-controller - >/dev/null <<-'HCL'
		path "sys/policies/acl/wyrwood-*" { capabilities = ["create", "read", "update", "delete", "list"] }
		path "auth/approle/role/wyrwood-*" { capabilities = ["create", "read", "update", "delete", "list"] }
		path "auth/approle/role/wyrwood-*/role-id" { capabilities = ["read"] }
		path "auth/approle/role/wyrwood-*/secret-id" { capabilities = ["create", "update"] }
		path "sys/wrapping/wrap" { capabilities = ["update"] }
		path "transit/keys" { capabilities = ["list"] }
		path "transit/keys/*" { capabilities = ["create", "read", "update", "list"] }
		path "ssh/roles" { capabilities = ["list"] }
		path "ssh/roles/*" { capabilities = ["create", "read", "update", "list"] }
		path "auth/token/renew-self" { capabilities = ["update"] }
	HCL
	bao write auth/approle/role/wyrwood-controller token_policies=wyrwood-controller token_ttl=1h >/dev/null
	bao kv put kv/teams/teal/example value=teal-example-value >/dev/null
	bao write -f transit/keys/teal-github type=ed25519 >/dev/null
	bao write ssh/roles/teal-hosts key_type=ca allow_user_certificates=true \
		allowed_users=deploy default_user=deploy ttl=30m >/dev/null
	role_id=$(bao read -field=role_id auth/approle/role/wyrwood-controller/role-id)
	bao write -f -field=secret_id auth/approle/role/wyrwood-controller/secret-id >"$root/controller/secret-id"
	chmod 600 "$root/controller/secret-id"

	# The mock provider signs every request in as one operator in the
	# wyrwood-operators group, without a login form.
	docker run -d --name wyrwood-demo-oidc -p "127.0.0.1:$oidc_port:8080" \
		-e JSON_CONFIG="$(jq -cn '{interactiveLogin: false, tokenCallbacks: [{issuerId: "demo", tokenExpiry: 3600,
			requestMappings: [{requestParam: "grant_type", match: "*", claims: {
				sub: "operator-1", aud: ["wyrwood"], name: "Avery Operator", email: "avery@example.test",
				groups: ["wyrwood-operators"]}}]}]}')" \
		ghcr.io/navikt/mock-oauth2-server:2.1.10 >/dev/null
	wait_for "the OpenID Connect provider" curl -fsS "http://localhost:$oidc_port/demo/.well-known/openid-configuration"
	echo demo-client-secret >"$root/controller/client-secret"
	chmod 600 "$root/controller/client-secret"

	cat >"$root/controller/controller.yml" <<-YAML
		http:
		  listen: 127.0.0.1:$http_port
		ssh:
		  listen: 127.0.0.1:$ssh_port
		state:
		  directory: $root/controller/state
		openbao:
		  address: http://127.0.0.1:$bao_port
		  approle:
		    role-id: $role_id
		    secret-id-file: $root/controller/secret-id
		oidc:
		  provider-name: Example ID
		  issuer: http://localhost:$oidc_port/demo
		  client-id: wyrwood
		  client-secret-file: $root/controller/client-secret
		  redirect-url: http://localhost:$http_port/auth/callback
		  allowed-groups:
		    - wyrwood-operators
	YAML
	mkdir -p "$root/controller/state"
	setsid "$root/bin/wyrwood" controller serve --config "$root/controller/controller.yml" \
		</dev/null >"$root/controller.log" 2>&1 &
	echo $! >"$root/controller.pid"
	wait_for "the controller" curl -fsS -o /dev/null "http://localhost:$http_port/"

	# The agent's engine runs beside the host's so the demo reports only its
	# own workloads, on its own bridge. Workloads need no network: the sockets
	# are files.
	sudo mkdir -p "$engine"
	sudo ip link add wyrwood-demo0 type bridge
	sudo ip address add 172.31.250.1/24 dev wyrwood-demo0
	sudo ip link set wyrwood-demo0 up
	# shellcheck disable=SC2024 # the log belongs to the invoking user
	sudo sh -c "exec dockerd --host 'unix://$engine/docker.sock' --data-root '$engine/data' \
		--exec-root '$engine/exec' --pidfile '$engine/docker.pid' \
		--containerd-namespace wyrwood-demo --containerd-plugins-namespace wyrwood-demo-plugins \
		--bridge wyrwood-demo0 --iptables=false --ip6tables=false --storage-driver vfs" \
		</dev/null >"$root/engine.log" 2>&1 &
	wait_for "the demo engine" engine_docker info
	docker save "$workload_image" | engine_docker load --quiet >/dev/null
	for name in teal-api teal-web amber-worker; do
		engine_docker run -d --name "$name" --network none --entrypoint sleep "$workload_image" infinity >/dev/null
	done

	sudo install -d -m 0755 /etc/wyrwood
	sudo tee /etc/wyrwood/agent.yml >/dev/null <<-YAML
		controller:
		  url: ssh://127.0.0.1:$ssh_port
		engine:
		  socket: $engine/docker.sock
		  allow-recreate: true
	YAML
	fingerprint=$("$root/bin/wyrwood" controller host-key --config "$root/controller/controller.yml")
	# shellcheck disable=SC2024 # the log belongs to the invoking user
	sudo "$root/bin/wyrwood" agent login "ssh://127.0.0.1:$ssh_port" --accept-fingerprint "$fingerprint" \
		>"$root/login.log" 2>&1 || true
	echo "controller: http://localhost:$http_port"
}

agent() {
	sudo -b sh -c "exec '$root/bin/wyrwood' agent daemon >'$root/agent.log' 2>&1" </dev/null >/dev/null 2>&1
}

down() {
	sudo pkill -f "^$root/bin/wyrwood agent daemon" 2>/dev/null || true
	if [ -f "$root/controller.pid" ]; then
		kill "$(cat "$root/controller.pid")" 2>/dev/null || true
	fi
	docker rm --force --volumes wyrwood-demo-bao wyrwood-demo-oidc >/dev/null 2>&1 || true
	if sudo test -S "$engine/docker.sock"; then
		engine_docker rm --force --volumes teal-api teal-web amber-worker >/dev/null 2>&1 || true
		sudo kill "$(sudo cat "$engine/docker.pid")" 2>/dev/null || true
		for _ in $(seq 1 100); do
			sudo test -e "$engine/docker.pid" || break
			sleep 0.2
		done
	fi
	sudo ip link delete wyrwood-demo0 2>/dev/null || true
	if demo_owns_agent_paths; then
		sudo rm -rf -- "${agent_paths[@]}"
	elif [ -f "$owned" ]; then
		echo "agent configuration does not name the demo controller; leaving ${agent_paths[*]} in place" >&2
	fi
	rm -f -- "$owned"
	case "$root" in
	/tmp/wyrwood-demo*) sudo rm -rf -- "$root" ;;
	esac
}

case "${1:-}" in
up) up ;;
agent) agent ;;
down) down ;;
*)
	echo "usage: $0 up|agent|down" >&2
	exit 2
	;;
esac
