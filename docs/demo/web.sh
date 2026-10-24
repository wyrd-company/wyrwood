#!/usr/bin/env bash
# ---
# relationships:
#   demonstrates: overview
#   references:
#     - web-interface
#     - policy
# ---
#
# Records the web interface half of the demo with agent-browser against the
# site docs/demo/stack.sh started: sign in, approve the agent, write a policy,
# bind a container, and read keys and events. Writes the video to
# $WYRWOOD_DEMO_ROOT/web.mp4 and the documentation screenshots to
# docs/user/assets.
set -euo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
root=${WYRWOOD_DEMO_ROOT:-/tmp/wyrwood-demo}
site=http://localhost:18088
assets=$repository/docs/user/assets
export AGENT_BROWSER_SESSION=wyrwood-demo-web

browse() {
	agent-browser "$@" >/dev/null
}

shot() {
	browse screenshot "$assets/$1.png"
}

hold() {
	sleep "$1"
}

mkdir -p "$assets"
browse set viewport 1280 800
browse open "$site/"
browse cookies clear
browse reload
browse record start "$root/web.mp4" --cursor
hold 2

# Sign in through the identity provider.
browse find role button click --name "Continue with Example ID"
browse wait --text "Pending approval"
hold 2.5
shot web-agents

# Approve the pending agent key, then start the agent.
browse find role button click --name "Approve agent"
browse wait --text "Approved agents"
"$repository/docs/demo/stack.sh" agent
hold 2
for _ in $(seq 1 30); do
	browse reload
	if agent-browser get text main | grep -q "Connected"; then
		break
	fi
	sleep 1
done
hold 2.5

# Write a policy: HCL, the SSH identities it offers, and the contract.
browse find role link click --name "Policies"
hold 1.5
browse open "$site/policies/edit"
hold 1
browse type "#name" "teal"
browse find role button click --name "Raw HCL"
browse fill "#hcl" 'path "kv/data/teams/teal/*" {
  capabilities = ["read"]
}
path "transit/keys/teal-github" {
  capabilities = ["read"]
}
path "transit/sign/teal-github" {
  capabilities = ["update"]
}
path "ssh/sign/teal-hosts" {
  capabilities = ["update"]
}'
hold 1
browse find role checkbox check --name "Agent token renewal"
browse find role button click --name "Graphical paths"
browse find role checkbox click --name "teal-github" --exact
browse find role checkbox click --name "teal-hosts" --exact
hold 1.5
browse find role button click --name "Save and validate"
browse wait --text "Revision 1"
hold 2.5
shot web-policy

# Bind a reported container to the policy.
browse find role link click --name "Containers"
browse wait --text "teal-api"
hold 1.5
browse find text "teal-api" click
browse wait --text "Binding settings"
browse find role checkbox click --name "teal" --exact
browse select "#binding-enforcement" "recreate"
hold 1
browse click 'input[name=understood]'
hold 1.5
shot web-bind
browse find role button click --name "Bind policies"
for _ in $(seq 1 60); do
	if agent-browser get text main | grep -q "Conforms"; then
		break
	fi
	sleep 1
	browse reload
done
hold 1.5
browse find text "teal-api" click
browse wait --text "Contract check"
hold 3
shot web-containers

# OpenBao keys and the event history.
browse find role link click --name "OpenBao keys"
hold 3
shot web-keys
browse find role link click --name "Events"
hold 3.5
shot web-events

browse record stop
browse close
