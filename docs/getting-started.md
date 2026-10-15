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
sudo wyrwood agent service start
```

Sign in to the controller's web interface through your identity provider,
open **Agents**, and approve the pending key after comparing its fingerprint
with the one the login command printed. The host's containers appear once
the agent reports in.

![Agents page with one key pending approval](assets/web-agents.png)

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

An access group is effectively required for non-root containers running as
another UID than the agent. Without it, the agent owns the directory (`0700`)
and sockets (`0600`); with it, their modes are `0750` and `0660`.

On each host, add the agent user to the chosen group and restart the agent.
For access group 1000:

```bash
getent group 1000
sudo usermod -aG <host-group-name> wyrwood
sudo systemctl restart wyrwood-agent
```

Replace `<host-group-name>` with the host group name for GID 1000. Create a
host group with that GID first if none exists. Packages add `wyrwood` only to
`docker`. Members of the access group who can reach these sockets can use the
binding's OpenBao and SSH permissions. See [Access group](configuration.md#access-group).

![Policy editor with a saved policy](assets/web-policy.png)

## Bind a container

Open **Containers**, select the container, and choose the policy. The
controller binds by the most stable key the container offers and shows which
one it used. The agent creates the container's consumer directory, obtains
its OpenBao token, and checks the contract.

![Binding a container to a recreate policy](assets/web-bind.png)

A container created without the mount is reported as non-conforming. Either
add the mount and environment to the container's definition and recreate it
yourself, or set the policy's enforcement to `recreate` and bind again. A
recreate stops, removes, and creates the container once. Anything outside a
mount or volume is discarded, and an attached editor session reconnects.

![A bound container that conforms to its contract](assets/web-containers.png)

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
