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
# bind a container, and read keys and events, then runs docs/demo/phone.sh.
# Writes the video to $WYRWOOD_DEMO_ROOT/web.mp4 and the documentation
# screenshots to docs/user/assets.
set -euo pipefail

repository=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
root=${WYRWOOD_DEMO_ROOT:-/tmp/wyrwood-demo}
site=http://localhost:18088
assets=$repository/docs/user/assets
export AGENT_BROWSER_SESSION=${AGENT_BROWSER_SESSION:-wyrwood-demo-web}
trap 'agent-browser close >/dev/null 2>&1 || true' EXIT

browse() {
	agent-browser "$@" >/dev/null
}

shot() {
	browse eval "document.fonts.ready.then(() => true)"
	browse screenshot --full "$assets/$1.png"
}

hold() {
	sleep "$1"
}

tab() {
	browse find role tab click --name "$1"
}

# Fails the recording when the page disagrees: the browser's own state is the
# only proof of what it does with a field on a hidden tab.
expect_page() {
	local got
	got=$(agent-browser eval "$1")
	if [ "$got" != "\"$2\"" ]; then
		echo "web.sh: $1 = $got, want $2" >&2
		exit 1
	fi
}

mkdir -p "$assets"
browse set viewport 1280 800
browse open "$site/"
browse cookies clear
browse reload
if [ "${WYRWOOD_DEMO_SCREENSHOTS_ONLY:-0}" != 1 ]; then
	browse record start "$root/web.mp4" --cursor
fi
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
browse wait --text "Connected"
shot web-versions

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
tab "SSH identities"
browse find role checkbox click --name "teal-github" --exact
browse find role checkbox click --name "teal-hosts" --exact
hold 1.5
browse find role button click --name "Save and validate"
browse wait --text "Revision 1"
hold 2.5
tab "OpenBao policy"

# Bind a reported container to the policy.
browse find role link click --name "Bindings"
browse wait --text "No bindings yet"
hold 1.5
browse find role link click --name "Add binding"
browse wait --text "teal-api"
hold 1.5
shot web-add-binding
# A key typed for a container no agent reports yet, with its directory name.
browse find role link click --name "Bind by typed key"
browse wait --text "Container key"
browse select "#typed-agent" "$(hostname)"
browse select "#typed-kind" "compose"
browse fill "#typed-value" "shop/web"
browse fill "#typed-directory" "shop-web"
browse find role checkbox click --name "teal" --exact
expect_page "document.querySelector('input[name=key]').value" "compose:shop/web"
# The typed key and directory name keep the 44 pixel control height and the
# monospace font of the summary's values.
expect_page "(() => { const mono = getComputedStyle(document.querySelector('dd.mono')).fontFamily; return ['typed-value', 'typed-directory'].every((id) => { const style = getComputedStyle(document.getElementById(id)); return style.fontFamily === mono && parseFloat(style.height) >= 44; }) ? 'ok' : 'no'; })()" ok
browse eval "window.scrollTo(0, 0)"
hold 1.5
shot web-bind-typed
browse find role link click --name "Back to Add binding"
browse wait --text "teal-api"
browse find role link click --name "Add binding for teal-api"
browse wait --text "Bind by key"
browse find role checkbox click --name "teal" --exact
hold 1.5
shot web-bind
tab "Settings"
# Use the real agent-reported root group for this root workload.
browse select "#binding-group" "0"
browse select "#binding-enforcement" "recreate"
hold 1
browse click 'input[name=understood]'
hold 1.5
shot web-bind-settings

# A required field on a hidden tab is revealed, not left to refuse in silence.
browse focus "#binding-ttl"
browse press Control+a
browse press Backspace
tab "Key and policies"
browse find role button click --name "Bind policies"
expect_page 'document.querySelector("[role=tab][aria-selected=true]").textContent' Settings
expect_page 'document.activeElement.id' binding-ttl
browse press 1

browse find role button click --name "Preview effective policy"
browse wait --text "Previewed effective policy"
hold 1.5
shot web-bind-effective
browse find role button click --name "Bind policies"
browse wait --text "Policy bound"
for _ in $(seq 1 60); do
	if agent-browser get text main | grep -q "Conforms"; then
		break
	fi
	sleep 1
	browse reload
done
browse wait --text "Conforms"
tab "Status"
browse wait --text "Contract check"
hold 3
shot web-binding
tab "Container setup"
browse wait --text "Host source"
shot web-container-setup
tab "Policies"
hold 1
shot web-binding-policies
tab "Settings"
hold 1
shot web-binding-settings
tab "Effective policy"
hold 1
shot web-binding-effective

# Return to the list, which shows the binding and its state.
browse find role link click --name "Back to bindings"
browse wait --text "Filter bindings"
hold 2
shot web-bindings

# The policy lists the binding it now has.
browse open "$site/policies/edit?name=teal"
browse wait --text "1 binding on 1 agent"
hold 2
shot web-policy
tab "SSH identities"
hold 1
shot web-policy-identities
tab "Container contract"
hold 1
shot web-policy-contract
browse find role link click --name "1 binding on 1 agent"
expect_page 'document.activeElement.getAttribute("role")' tabpanel
browse wait --text "What a change to this policy affects"
hold 2
shot web-policy-bindings

# A bound policy cannot be deleted, and the screen says what blocks it.
browse find role link click --name "Delete policy"
browse wait --text "cannot be deleted"
hold 2
shot web-policy-delete

# A bound policy can be renamed, and the screen says who gets a fresh credential.
browse open "$site/policies/edit?name=teal"
browse wait --text "1 binding on 1 agent"
browse find role link click --name "Rename"
browse wait --text "fresh credential"
hold 2
shot web-policy-rename

# A policy that no binding selects can be deleted, through its confirm screen.
browse open "$site/policies/edit"
browse type "#name" "draft"
browse find role button click --name "Save and validate"
browse wait --text "Revision 1"
browse find role link click --name "Rename"
browse wait --text "New name"
browse fill "#new-name" "scratch"
browse find role button click --name "Rename policy"
browse wait --text "Policy renamed"
browse find role link click --name "Delete policy"
browse wait --text "wyrwood-scratch"
hold 2
shot web-policy-delete-confirm
browse find role button click --name "Delete policy"
browse wait --text "Policy deleted"
hold 2

# OpenBao keys and the event history.
browse find role link click --name "OpenBao keys"
hold 3
shot web-keys
browse find role link click --name "Events"
hold 3.5
shot web-events

# Account and security use the same signed-in operator as the workflow.
browse find role button click --name "Account"
browse wait --text "Sign out"
shot web-account-menu
browse find role menuitem click --name "Security" --exact
browse wait --text "Admitted through group"
shot web-security

# Inspect the effective controller configuration through the normal navigation.
browse find role link click --name "Settings" --exact
browse wait --text "Effective controller settings loaded at startup"
browse wait --text "Update checks"
shot web-settings

# One policy gives each binding its own path. This comes last and saves no
# binding, so that the earlier screens show the one binding of the walk-through.
browse open "$site/policies/edit"
browse type "#name" "shared-key"
browse find role button click --name "Raw HCL"
browse fill "#hcl" 'path "kv/data/teams/{{binding.team}}/*" {
  capabilities = ["read"]
}'
browse find role button click --name "Save and validate"
browse wait --text "Revision 1"
browse open "$site/bindings"
browse find role link click --name "Add binding"
browse wait --text "teal-web"
browse find role link click --name "Add binding for teal-web"
browse wait --text "Bind by key"
browse find role checkbox click --name "shared-key" --exact
browse wait --text "Values for this binding"
browse fill "#binding-value-team" "teal"
hold 1
browse eval "window.scrollTo(0, 0)"
shot web-bind-values
browse find role button click --name "Preview effective policy"
browse wait --text "Previewed effective policy"
expect_page 'document.querySelector("[aria-label=\"Previewed effective policy\"] code").textContent.includes("kv/data/teams/teal/*").toString()' true
hold 1.5
shot web-bind-values-effective

# Approve an operator key with a grant, and leave a second key pending. This comes
# last, so that no earlier screen shows its pending count.
"$repository/docs/demo/stack.sh" operator-login sample-script
browse open "$site/operator-keys"
browse wait --text "Pending operator keys"
browse find role checkbox click --name "$(hostname)" --exact
browse find role checkbox click --name "shared-key" --exact
browse find role checkbox click --name "Create and remove bindings"
browse wait --text "Can create and remove bindings on $(hostname)"
browse find role button click --name "Approve key"
browse wait --text "Operator key approved"
# Choose a grant for the second key, so that the screen shows its summary.
"$repository/docs/demo/stack.sh" operator-login workspace-tool
browse reload
browse wait --text "Pending operator keys"
browse find role checkbox click --name "$(hostname)" --exact
browse find role checkbox click --name "All policies, including policies created later"
browse wait --text "Can read every policy"
hold 1
browse eval "window.scrollTo(0, 0)"
shot web-operator-keys

if [ "${WYRWOOD_DEMO_SCREENSHOTS_ONLY:-0}" != 1 ]; then
	browse record stop
fi

# The phone-width test needs the policy, the binding, and the pending key above.
"$repository/docs/demo/phone.sh"
browse close
