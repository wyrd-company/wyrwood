---
relationships:
  describes: wyrwood
  references:
    - per-user-agent-proxy
---

# Wyrwood

Wyrwood gives containers stable, deliberately scoped access to keys held by a
host SSH agent. It runs as the logged-in user, connects to one SSH-agent
compatible upstream socket, and publishes a separate consumer socket for each
container.

Each consumer has an explicit public-key fingerprint allowlist. Wyrwood exposes
identity listing and signing through the consumer socket while rejecting agent
administration and unrecognized extensions. A consumer keeps the same mounted
directory when the upstream agent or Wyrwood replaces a socket.

## Container integration

Wyrwood is independent of the container runtime. Mount a consumer's parent
directory into the container and set the container's `SSH_AUTH_SOCK` to the
socket's mounted path. Mounting the directory, rather than the socket file,
allows socket replacement to remain visible inside a running container.

## Project direction

The [concept](docs/concepts/wyrwood.yml) defines the product and the
[technical design](docs/technical-designs/per-user-agent-proxy.yml) defines its
architecture and security boundaries.

The repository currently provides the Go command foundation used by the daemon,
command-line interface, and terminal user interface.

```console
task check
task build
./wyrwood --help
```
