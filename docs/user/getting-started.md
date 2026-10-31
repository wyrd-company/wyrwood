---
title: Getting started
order: 3
product: wyrwood
relationships:
  references:
    - command-line-interface
    - policy
    - container-contract
---

This walk-through enrolls one host, writes one policy, and binds one
container. Use the controller web interface for policy and binding changes;
run the host and container commands where indicated.

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
the agent reports in. For a controller that also runs its local agent, follow
[Controller with a local agent](install.md#controller-with-a-local-agent) to
enroll and approve that host; do not start a separate agent daemon.

![Agents page with one key pending approval](assets/web-agents.png)

## Write a policy

Open **Policies → New policy** and enter a name, such as `teal`.
Use **Graphical paths** to add paths and select their capabilities, or
**Raw HCL** to paste the example below. Select the SSH identities and keep
the default contract for this example. Choose **Save and validate** and check
that OpenBao accepts the policy. A policy has three parts:

1. The OpenBao policy, in HCL. For example, read access to one KV path and
   signing with one Transit key. Use **Agent token renewal** to control
   automatic renewal. Wyrwood supplies the lifecycle grants:

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
   and sets `SSH_AUTH_SOCK` and `VAULT_ADDR` to the sockets inside it.

When binding, choose **Access group** from the groups reported by the running
host agent. The container processes must retain that numeric GID as a primary
or supplementary group. A capable agent also offers a custom numeric GID.
See [Access group](configuration.md#access-group) for stale reports and host
group changes. Leave binding enforcement at `report` unless you want one
recreate with the mount applied on first bind. Preview the effective policy
before saving. TTL, access group, and enforcement are binding settings.

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
host group with that GID first if none exists. Use a separate group from
`docker`; the agent has no direct Docker access. Members of the access group
who can reach these sockets can use the
binding's OpenBao and SSH permissions. See [Access group](configuration.md#access-group).

![Policy editor with a saved policy](assets/web-policy.png)

## Bind a container

Open **Containers**, select the container, then select one or more policies
and binding settings. Use **Preview effective policy** to inspect the
combined policy, then **Bind policies** to save. The
controller binds by the most stable key the container offers and shows which
one it used. The agent creates the container's consumer directory, obtains
its OpenBao token, and checks the contract.

![Binding policies to a container](assets/web-bind.png)

A container created without the mount is reported as non-conforming. Either
add the mount and environment to the container's definition and recreate it
yourself, or set the binding's enforcement to `recreate` and bind again. A
recreate stops, removes, and creates the container once. Anything outside a
mount or volume is discarded, and an attached editor session reconnects.

For a manual recreate, use this order:

1. Bind the existing container and wait for the agent to create
   `/run/wyrwood/containers/<container-name>` on the host. Use the container's
   Docker name for this path, including when the binding uses a label key.
2. Add the mount and environment variables to the replacement definition.
   Use `--mount type=bind` so Docker fails if the source directory is absent.
3. Remove the old container and create the replacement with the same Docker
   name and binding key. Keep the Docker name even when the binding uses a
   label key: the consumer directory is named after the container. The agent
   keeps that directory through the gap and restores its sockets when the
   replacement receives its binding.

For example, replace a container named `app`:

```bash
docker rm -f app
docker run -d --name app \
  --mount type=bind,src=/run/wyrwood/containers/app,dst=/run/wyrwood \
  -e SSH_AUTH_SOCK=/run/wyrwood/ssh-agent.sock \
  -e VAULT_ADDR=unix:///run/wyrwood/vault.sock \
  alpine sleep infinity
```

Keep the image, other mounts, labels, and options your application needs.
Avoid `-v` for this mount: Docker creates a missing source as root, and the
agent rejects directories owned by another user.

If Docker has already created a root-owned source, stop the container before
repairing it. Check that the directory is empty, then replace it with one owned
by the agent service user. For the default service configuration without an
access group:

```bash
docker stop app
sudo rmdir /run/wyrwood/containers/app
sudo install -d -o wyrwood -g wyrwood -m 0700 /run/wyrwood/containers/app
docker start app
```

Stop if `rmdir` fails; do not recursively delete the directory. The agent applies
its configured access group when it opens the repaired directory. Repair before
starting the container so its bind mount refers to the new directory.

![A bound container that conforms to its contract](assets/web-containers.png)

For a devcontainer named `app`, set the Docker name explicitly so rebuilds
reuse its consumer directory. Use the existing container's Docker name in both
`runArgs` and the mount source, and choose a name unique on that Docker host:

```json
{
  "runArgs": ["--name", "app"],
  "mounts": [
    "source=/run/wyrwood/containers/app,target=/run/wyrwood,type=bind"
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
