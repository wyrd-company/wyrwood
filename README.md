---
relationships:
  references:
    - wyrwood
    - linux-per-user-agent-proxy
    - command-line-interface
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

The Linux integration gate runs this topology against a real Docker container
and real Unix sockets. It keeps one downstream connection open while policies
change, replaces a controllable upstream agent at the same path, verifies
session-binding replay, and recreates the daemon endpoint without restarting or
remounting the container.
The gate requires a reachable Linux Docker daemon and pulls `ubuntu:24.04` only
when that image is absent.

## Command-line use

Create the initial owner-only configuration from the current `SSH_AUTH_SOCK`,
install and start the systemd user service, and ask that daemon to apply it:

```console
wyrwood init
wyrwood service install
wyrwood service start
wyrwood apply
```

Runtime commands always use the daemon's owner-authenticated local control
socket. They do not accept alternate configuration or control paths.

```console
wyrwood keys
wyrwood status
wyrwood events --limit 50
wyrwood status --output json
```

Inspect and change durable configuration through the same control socket. Each
change requires the exact revision returned by `configuration show`; a saved
change remains unapplied until the explicit `apply` command succeeds.

```console
revision=$(wyrwood configuration show --output json | jq -r '.result.revision')
wyrwood configuration set-upstream --revision "$revision" --socket /tmp/source.sock

revision=$(wyrwood configuration show --output json | jq -r '.result.revision')
wyrwood consumer put --revision "$revision" --name sample \
  --socket /tmp/sample/endpoint.sock \
  --fingerprint SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

wyrwood apply
```

`consumer put` replaces the complete consumer value and fingerprint allowlist.
Pass the opaque `--id` from `configuration show` to replace an existing
consumer; omit it to create one. `consumer retire` requires that identifier.

Human-readable output is the default. `--output json` emits a versioned,
closed JSON object for automation. Successful output goes to standard output;
categorical actionable errors go to standard error. Append `--help` to a
management command to show its specific options. Service installation enables
login startup and safely restarts an already-active daemon only when its unit
changes. `wyrwood service status --output json` provides the same closed output
contract for automation. Starting or stopping an absent unit reports the distinct
`service-not-installed` category and directs the user to install it first.

Run `wyrwood tui` from an interactive terminal to use the same daemon control
interface. The dashboard, upstream view, consumer detail, new-consumer form,
and timeout settings expose keyboard-only configuration and diagnostics. Saved
edits remain visibly unapplied until the explicit Apply action succeeds. Dirty
edits require confirmation before discard or exit, and a stale revision keeps
the candidate available for reload or cancellation instead of overwriting a
newer YAML document. Run `wyrwood tui --help` for its invocation grammar; the
persistent footer and expanded `?` help show the keys available in each view.

## Installation

### APT

Install the repository key and source definition, then install Wyrwood:

```console
sudo install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://repo.wyrd.foo/pubkey.gpg |
  sudo tee /etc/apt/keyrings/wyrd-company.gpg >/dev/null
echo "deb [signed-by=/etc/apt/keyrings/wyrd-company.gpg] \
https://repo.wyrd.foo/apt stable main" |
  sudo tee /etc/apt/sources.list.d/wyrd-company.list >/dev/null
sudo apt update
sudo apt install wyrwood
```

### RPM

Install the repository definition and Wyrwood with DNF:

```console
sudo curl -fsSL https://repo.wyrd.foo/wyrd.repo \
  -o /etc/yum.repos.d/wyrd.repo
sudo dnf install wyrwood
```

### Arch User Repository

The prebuilt Arch User Repository (AUR) package is `wyrwood-bin`. Install it
with an AUR helper, for example:

```console
paru -S wyrwood-bin
```

After upgrading through any package manager, restart an active Wyrwood daemon
so it runs the new executable:

```console
wyrwood service stop
wyrwood service start
```

The consumer endpoints are unavailable between those two commands. A new
installation still requires the initialization and service commands in
[Command-line use](#command-line-use).

## Release operations

A bare stable SemVer tag starts the package publisher compatibility preflight.
The preflight builds real archive, DEB, and RPM snapshot artifacts with the tag's
version, then validates the manifest, immutable inbox path, package staging, and
AUR rendering through one full-commit-pinned checkout of `repo.wyrd.foo`. The
GitHub Release job cannot start unless that contract passes.

A successful Release workflow retains its exact package manifest for 90 days
and automatically submits it to `repo.wyrd.foo`. Manual package recovery
requires both the original successful Release workflow run ID and its tag. It
downloads only that run's retained manifest and fails closed when the artifact
has expired or is unavailable; it never recomputes digests from mutable GitHub
Release assets. Package submission uses these product-repository secrets:

- `REPO_WYRD_FOO_PUBLISHER_APP_ID`
- `REPO_WYRD_FOO_PUBLISHER_PRIVATE_KEY`

GitHub does not emit a new workflow event for a release created with the Release
workflow's `GITHUB_TOKEN`. After **every** automated release, manually dispatch
the `Publish docs` workflow with the same tag. This remains required unless the
release workflow deliberately adopts authentication that can trigger the
release event. Documentation publishing uses these separate secrets:

- `WYRD_TOOLS_DOCS_PUBLISHER_APP_ID`
- `WYRD_TOOLS_DOCS_PUBLISHER_PRIVATE_KEY`

## Project direction

The [concept](docs/concepts/wyrwood.yml) defines the product, the
[Linux technical design](docs/technical-designs/linux-per-user-agent-proxy.yml)
defines its architecture and security boundaries, and the
[command-line specification](docs/specifications/command-line-interface.yml)
defines stable output and exit statuses.

```console
task check
task test:integration:management
task test:integration:linux
task build
task release:snapshot
```
