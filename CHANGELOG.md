# Changelog

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
