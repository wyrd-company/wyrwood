---
title: Policies and contracts
order: 4
docs: true
relationships:
  references:
    - policy
    - configuration
---

Policy lives on the controller. Agents receive the policies that match their
containers and cache them so a controller restart does not interrupt running
containers.

## Policy document

```yaml
name: teal-devcontainer
openbao:
  policy: |
    path "kv/data/teams/teal/*" { capabilities = ["read"] }
  token-ttl: 1h
ssh:
  transit-keys:
    - teal-github
  ca-roles:
    - homelab
contract:
  mount-target: /run/wyrwood
  env:
    SSH_AUTH_SOCK: "{mount-target}/ssh-agent.sock"
    VAULT_ADDR: "unix://{mount-target}/vault.sock"
  access-group: 1000
  enforcement: report
```

The controller validates the HCL through OpenBao before saving and writes it
as `wyrwood-teal-devcontainer`. Every Transit key and SSH role the policy
names must exist under the controller's configured mounts and must also be
permitted by the HCL.

## Bindings

A binding attaches one policy to one container key on one agent. Keys are
tried in order: devcontainer identity labels, compose project and service
labels, container name. The controller creates one AppRole per binding with
the policy attached. Changing the policy updates the AppRole, and the agent
obtains a new token on the push. Deleting the binding deletes the AppRole and
revokes its tokens.

## Contract enforcement

`report` is the default. The agent checks the mount, the environment names and
values, and the access group on every reconcile and reports what is missing.

`recreate` makes the agent apply the contract once, when the policy is first
bound to a container. The agent stops, removes, and creates the container from
its inspected definition with the mount and environment merged in. Later drift
is reported, not recreated. The host's agent configuration must also allow
recreate; otherwise the binding is reported as non-conforming with that
reason.

## Agent configuration

`/etc/wyrwood/agent.yml` holds only what is needed to reach the controller
and the engine:

```yaml
controller:
  url: ssh://controller.example.internal:2222
engine:
  socket: /var/run/docker.sock
  allow-recreate: false
```

The agent key, accepted controller fingerprint, cached policy, and events live
under `/var/lib/wyrwood`. No token or secret is ever written there.

## Controller configuration

`/etc/wyrwood/controller.yml` names the listen addresses, the state
directory, and the OpenBao connection. The AppRole secret identifier is read
from a file:

```yaml
http:
  listen: 127.0.0.1:8080
ssh:
  listen: 0.0.0.0:2222
openbao:
  address: https://openbao.example.internal:8200
  approle:
    role-id: REPLACE_WITH_ROLE_ID
    secret-id-file: /run/secrets/openbao-secret-id
  transit-mount: transit
  ssh-mount: ssh
```

The controller's own OpenBao policy should cover only the Wyrwood prefix:
`sys/policies/acl/wyrwood-*`, `auth/approle/role/wyrwood-*`,
`sys/wrapping/wrap`, and the Transit and SSH mounts it manages.
