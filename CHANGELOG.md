# Changelog

## 0.3.0

### Features

- Add graphical policy paths with KV metadata browsing, identity toggles, environment controls, and duration pickers while preserving raw HCL.
- Add a separate CLI provisioning flow for OIDC secret admins on selected OpenBao KV v2 mounts, with namespace UI links in the sidebar and policy editor.
- Warn in the policy editor when HCL reaches outside configured mounts, with a shared catalog of expected secret engines.
- Add per-identity not-forwardable SSH policy selectors and refuse signing after a verified forwarding session bind.
- Add a separate Engine proxy to enforce the host recreate permission.
- Allow container bindings to select multiple policies and preview effective HCL, SSH identities, and contract requirements. Token TTL, access group, and enforcement belong to each binding. Binding tokens omit the implicit default policy; authors supply self-operation grants.
- Show controller and agent build versions, flag older agents, and add opt-in release checks with configurable interval and timeout. Agents that omit their version remain supported.

### Fixes

- Run repository checks and OpenBao-backed tests on pull requests and pushes to main.
- Report socket-access failure when a container user cannot be verified as a member of the policy access group.
- Migrate the controller web interface to React with shadcn/ui and Tailwind v4, embedded in the executable and container image.
- Turn the sidebar account element into an accessible menu with Security and sign out.
- Treat an overlapping token self-revocation as successful when OpenBao confirms the token cannot authenticate.

## 0.2.3

### Fixes

- Report non-conforming contracts when consumer sockets are unavailable or the container user cannot reach owner-only sockets.
- Document access-group setup and show group assignment failures in the web interface and agent container listing.
- Preserve consumer mount directories across manual container recreation so replacement containers receive their sockets.

## 0.2.2

### Fixes

- Enable the agent service at boot when starting package or archive installations; stopping the service preserves boot startup.
- Report OpenBao reachability correctly when a namespace is configured.
- Replace the placeholder concentric-circle mark with the Wyrwood tree emblem across the web interface: light and dark SVG variants in the app palette, an adaptive SVG favicon, a multi-size favicon.ico, and an Apple touch icon.

## 0.2.1

### Fixes

- Document a dedicated OpenBao namespace as the supported controller deployment, so that a compromised controller or operator can grant nothing outside Wyrwood's namespace. The controller's own policy and AppRole are named outside the `wyrwood-` prefix, and binding AppRoles accept only their own managed policy.

## 0.2.0

### Features

- Split Wyrwood into a controller and an agent. The controller owns policy, serves a web interface that operators sign in to through OpenID Connect with group-based admission, and manages OpenBao policies and AppRoles. The agent watches Docker Engine, binds containers to policy, and publishes a per-container vault socket and ssh-agent socket. Keys and secrets live in OpenBao; the host SSH-agent upstream, fingerprint allowlists, and terminal interface are removed.
