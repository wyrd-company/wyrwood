---
title: Getting started
order: 3
docs: true
relationships:
  references:
    - command-line-interface
    - policy
    - container-contract
---

This walk-through enrolls one host, writes one policy, and binds one
container.

## Enroll the agent

On the host, point the agent at the controller. The command generates the
agent's key pair, prints its fingerprint, and shows the controller's host-key
fingerprint for you to accept.

```bash
sudo wyrwood agent login ssh://controller.example.internal:2222
sudo systemctl enable --now wyrwood-agent
```

In the controller's web interface, open **Agents** and approve the pending
key. The host's containers appear once the agent reports in.

## Write a policy

Open **Policies** and create one. A policy has three parts:

1. The OpenBao policy, in HCL. For example, read access to one KV path and
   signing with one Transit key:

   ```hcl
   path "kv/data/teams/teal/*" {
     capabilities = ["read"]
   }
   path "transit/sign/teal-github" {
     capabilities = ["update"]
   }
   path "transit/keys/teal-github" {
     capabilities = ["read"]
   }
   ```

2. The SSH identities the agent socket should offer. Name the Transit key
   `teal-github`. Name an SSH-engine role if a host you reach trusts the
   OpenBao CA.

3. The contract. The default mounts the consumer directory at `/run/wyrwood`
   and sets `SSH_AUTH_SOCK` and `VAULT_ADDR` to the sockets inside it. Set
   the access group to the numeric group your container's processes use.
   Leave enforcement at `report` unless you want the agent to recreate the
   container with the mount applied when you bind it.

## Bind a container

Open **Containers**, select the container, and choose the policy. The
controller binds by the most stable key the container offers and shows which
one it used. The agent creates the container's consumer directory, obtains
its OpenBao token, and checks the contract.

A container created without the mount is reported as non-conforming. Either
add the mount and environment to the container's definition and recreate it
yourself, or set the policy's enforcement to `recreate` and bind again. A
recreate stops, removes, and creates the container once. Anything outside a
mount or volume is discarded, and an attached editor session reconnects.

For a devcontainer, the equivalent definition is:

```json
{
  "mounts": [
    "source=/run/wyrwood/containers/${devcontainerId},target=/run/wyrwood,type=bind"
  ],
  "containerEnv": {
    "SSH_AUTH_SOCK": "/run/wyrwood/ssh-agent.sock",
    "VAULT_ADDR": "unix:///run/wyrwood/vault.sock"
  }
}
```

## Use the sockets

Inside the container:

```bash
bao kv get kv/teams/teal/example
ssh-add -L
git -c core.sshCommand=ssh push
```

The first command carries the container's token without the container ever
seeing it. The second lists the Transit key. The third signs the push in
OpenBao.
