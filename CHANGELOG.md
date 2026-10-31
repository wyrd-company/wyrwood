# Changelog

## 0.4.1

### Features

- Show effective controller settings in a read-only web admin page with operator authorization and an explicit projection that excludes credentials and credential-file paths.
- Run the shared host agent inside the controller with opt-in local-agent configuration, retaining standalone enrollment, approval, Engine isolation, and local status commands. Join recreate workers and drain admitted operator requests before releasing durable state during shutdown.
- Choose binding access groups from the running agent’s reported process groups,
  reject known unassignable selections on the server, and explain unknown reports,
  host restarts, owner-only access, and container application group retention.

### Fixes

- Build the controller interface with pnpm 12 while preserving locked dependency versions.
- Update the controller SSH server to the supported Charm SSH and Wish modules, including authentication and connection handling fixes.
- Publish the user documentation from docs/user in the wyrd.foo v2 format, with a products map, structured install entries, highlights, the web interface screenshots as product media, and the product logo and favicon.
- Keep controller image builds working with Node.js 26 by installing Corepack explicitly.
- Keep Renovate updates for the OpenBao ACL parser on HCL 1 to preserve policy
  syntax compatibility and avoid adding an unused HCL 2 module.

## 0.4.0

### Features

- Show containers across all approved agents by default, with agent and text filters, sorting, and disconnected last-report state.
- Show copyable container mount and environment setup from the agent report and effective binding contract.
- Manage fixed token lookup and retirement grants and control actual agent renewal with a policy setting. Keep container renewal local and return real token metadata without revealing the credential.

### Fixes

- Submit package releases with the publisher action that accepts AUR service files and lifecycle hooks.
- Publish the account menu and version status screenshots with the wyrd.foo docs.
- Document a stopped controller-first upgrade procedure and include the container setup screenshot in published documentation.

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
