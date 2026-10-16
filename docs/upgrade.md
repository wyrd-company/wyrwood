---
title: Upgrade
order: 8
docs: true
relationships:
  references:
    - composable-policy-bindings
    - configuration
---

## Composable policy bindings

**This upgrade requires a clean controller state and a full reset of the
dedicated Wyrwood OpenBao namespace. There is no migration.** Existing stored
policies, bindings, approvals, inventories, sessions, keys, roles, secrets, and
tokens in those two locations are not preserved automatically.

Back up the controller state and configuration, authored HCL, policy and binding
selections, Transit and SSH key material where export is supported, and every
secret engine in the dedicated namespace. Keep secret backups in an approved
secret store. An OpenBao snapshot can protect the broader deployment, but its
restore affects the whole snapshot scope. Confirm backups before any deletion.

Stop the controller and agents. Reset only the controller's configured state
directory and its dedicated OpenBao namespace. Do not reset the parent or root
namespace or any other namespace. A reset of individual `wyrwood-*` policies
and roles is insufficient: reset the complete dedicated namespace, including
its controller AppRole, auth mount, secret-engine mounts, and tokens.

Recreate the dedicated namespace and rerun the OpenBao setup in
[Policies and contracts](configuration.md#openbao-namespace). Restore or recreate
the required keys and secrets, then supply the new controller role ID and secret
ID. Start the controller with an empty state directory. Recreate policies and
bindings, approve agents again, and verify the controller's new SSH fingerprint
through a trusted channel before accepting it on each agent. Reset agent state
and log in again when replacing the pinned fingerprint; preserve any required
local recreate journal evidence first. Check socket ownership and contract
conformance before resuming workloads.

Upgrade the **controller, agents, and CLI together**. The agent-controller
protocol, policy cache, and daemon control protocol use version 2. There are no
version 1 adapters. A version 1 agent stops receiving new tokens until upgraded;
existing tokens expire, and the namespace reset revokes them. Schedule an outage.
Automation consuming container JSON must use `policies` instead of `policy`.

Each new binding selects one or more reusable policies and owns token TTL,
maximum TTL, access group, and enforcement. Add these authored HCL grants to
policies whose tokens must renew:

```hcl
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }
path "auth/token/revoke-self" { capabilities = ["update"] }
```

Binding tokens no longer inherit OpenBao's `default` policy. Missing an explicit
renewal grant produces a visible warning, so deliberately non-renewing tokens
remain possible. OpenBao evaluates actual ACL capabilities.

After setup, verify there is no old controller database, no old binding AppRole
or token in the recreated namespace, and no stale agent cache in use. Confirm a
new binding token has exactly its selected `wyrwood-*` policies, with no
`default`, controller policy, or unrelated managed policy. Check a live container
can reach its sockets and that the agent renews its token.
