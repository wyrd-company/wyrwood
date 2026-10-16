---
relationships:
  references:
    - wyrwood
    - controller
    - agent
    - command-line-interface
---

# Wyrwood

Wyrwood delivers OpenBao-backed secrets and signing to containers through a
per-container directory of Unix sockets. A container holds no token, no key,
and no secret file.

A **controller** runs once per site as a container. It owns policy, serves a
web interface, and holds the only OpenBao credential that can write policies
and AppRoles. An **agent** runs on each Linux host with Docker Engine. It
enrolls with the controller over SSH, reports every container, binds
containers to policy, and publishes each bound container's sockets.

Inside a bound container the mounted directory holds `vault.sock`, an OpenBao
API endpoint that carries the container's own token on every request, and
`ssh-agent.sock`, a standard SSH agent whose identities are OpenBao Transit
keys and SSH-engine certificates. Policy changes take effect on the next
request. Private keys never exist on the host or in the container.

## Quick start

Run the controller. The image runs as user 65532, so the secret files must
be readable by that user; [Installation](docs/install.md) shows the
configuration and how to prepare them.

```console
docker run -d --name wyrwood-controller \
  -p 127.0.0.1:8080:8080 -p 2222:2222 \
  -v wyrwood-state:/var/lib/wyrwood \
  -v ./controller.yml:/etc/wyrwood/controller.yml:ro \
  -v ./secret-id:/run/secrets/openbao-secret-id:ro \
  -v ./oidc-client-secret:/run/secrets/oidc-client-secret:ro \
  ghcr.io/wyrd-company/wyrwood:latest
```

Enroll a host:

```console
sudo apt install wyrwood
sudo wyrwood agent login ssh://controller.example.internal:2222
sudo systemctl enable --now wyrwood-agent
```

Approve the agent, write a policy, and bind a container in the web interface.
Inside the container:

```console
bao kv get kv/teams/teal/example
ssh-add -L
```

The [documentation](docs/overview.md) covers installation, policies and
contracts, and operations.

## Project direction

The [concept](docs/concepts/wyrwood.yml) defines the product. The
[controller](docs/technical-designs/controller.yml) and
[agent](docs/technical-designs/agent.yml) designs define the architecture,
with the [container contract](docs/technical-designs/container-contract.yml),
[vault socket proxy](docs/technical-designs/vault-socket-proxy.yml), and
[ssh-agent endpoint](docs/technical-designs/ssh-agent-endpoint.yml) designs
covering each delivery path. Decisions live in `docs/decisions` and risks in
`docs/risks`.

## Development

Builds require Go, Node.js 24 with Corepack, and Task. Corepack uses the pnpm
version declared in `internal/web/frontend/package.json`. `task build` installs
from the frozen frontend lockfile and builds the interface for embedding in
`wyrwood`. The executable and controller image need no Node.js runtime or
external UI files. Generated frontend assets are not committed.

The interface sources are in `internal/web/frontend`. They use React,
TypeScript, shadcn/ui components, Tailwind v4, and Vite. `task check` checks
frontend types, formatting, and component tests alongside the Go gates.
`task test` builds a test-only React renderer so the Go workflow tests inspect
the same components that run in the browser. Set `WYRWOOD_BAO` to a `bao`
binary to run OpenBao-backed tests; those tests skip when it is unavailable.
After editing the UI, run `task build` and restart the controller. For
continuous asset builds, run `corepack pnpm run watch` in
`internal/web/frontend`, then rebuild and restart the Go controller to embed
each result.

```console
task check
task test
task build
```

Pull requests and pushes to `main` run `task ci`. This runs `task check` with
uncached, verbose tests and fails when OpenBao or real-engine prerequisites
are missing. CI installs OpenBao and pulls the test image. For local runs,
set `WYRWOOD_BAO` to a `bao` executable and `WYRWOOD_TEST_IMAGE` to a local
container image. `task test` permits prerequisite skips for development.

## Releases

Intentional is the only version and release mechanism. Record a change with
`intentional add`, and release with `intentional plan`, `apply`, and `tag`.
Tags are bare SemVer values. A pushed stable tag runs the package publisher
compatibility preflight, publishes the GitHub release, submits the package
manifest to `repo.wyrd.foo`, and publishes the controller image to
`ghcr.io/wyrd-company/wyrwood` with the workflow's own token. Package
submission uses these product-repository secrets:

- `REPO_WYRD_FOO_PUBLISHER_APP_ID`
- `REPO_WYRD_FOO_PUBLISHER_PRIVATE_KEY`

Dispatch the `Publish docs` workflow with the same tag after every automated
release; a release created with the Release workflow's `GITHUB_TOKEN` emits no
event that triggers it. Documentation publishing uses these separate secrets:

- `WYRD_TOOLS_DOCS_PUBLISHER_APP_ID`
- `WYRD_TOOLS_DOCS_PUBLISHER_PRIVATE_KEY`
