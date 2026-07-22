---
title: Getting started
order: 3
docs: true
relationships:
  references:
    - command-line-interface
    - configuration
    - linux-user-service
---

Wyrwood initializes from the current `SSH_AUTH_SOCK`. Start in the same Linux
login session as the host SSH agent whose keys you want to use.

## Initialize and start the daemon

Create the owner-only configuration, install the systemd user unit, and start
it:

```bash
wyrwood init
wyrwood service install
wyrwood service start
wyrwood status
```

`init` records the current upstream socket path. It never overwrites an existing
configuration. Service commands use the current user's systemd manager and do
not require `sudo`.

List the identities available from the upstream agent:

```bash
wyrwood keys
```

Fingerprints are authorization identities. Agent comments are display labels
only.

## Create a consumer

Every managed configuration change starts from the exact current revision. The
following example creates a consumer named `teal` with one allowed key:

```bash
runtime_root="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
revision=$(wyrwood configuration show --output json |
  jq -r '.result.revision')
wyrwood keys
read -r -p "Fingerprint to allow: " fingerprint

wyrwood consumer put \
  --revision "$revision" \
  --name teal \
  --socket "$runtime_root/teal/agent.sock" \
  --fingerprint "$fingerprint"
```

The consumer socket needs a dedicated parent directory. Wyrwood can create that
leaf directory when its ancestor already exists; it does not create missing
ancestors. Keep the socket path short enough for the Linux Unix-domain socket
limit.

Saving configuration does not alter the running policy. Apply it explicitly:

```bash
wyrwood apply
wyrwood status
```

## Mount the consumer directory

Mount the socket's parent directory into the container, then point the
container's `SSH_AUTH_SOCK` at the mounted socket. Mount the directory, not the
socket file, so replacement remains visible inside a running container.

```bash
docker run --rm -it \
  --mount type=bind,src="$runtime_root/teal",dst=/run/example \
  --env SSH_AUTH_SOCK=/run/example/agent.sock \
  debian:stable-slim
```

Any process that can reach the consumer socket shares its configured authority.
Use container runtime mounts and Linux filesystem permissions to limit that
access.
