# Changelog

## 0.5.0

### Breaking

- Controller state moves to schema 3, and a policy created under a name used before has a new OpenBao policy, `wyrwood-<name>--<number>`. A token that outlived the earlier policy has no access to the new one, and creating a policy under a used name stays supported. The controller migrates its database at startup: every row stays, existing policies keep `wyrwood-<name>`, existing assignments keep their identity, and live tokens stay valid. A 0.4.x controller refuses a schema 3 database at startup, so back up the state directory before upgrading. Agents and the controller upgrade together, as the stopped rollout requires: a 0.4.x agent rejects the assignment field that names a reused policy.

### Features

- The Containers page is now the Bindings page at `/bindings`. It lists every stored binding, including one whose container the agent no longer reports, which is marked `Not reported`. **Add binding** opens a screen that lists reported containers with no binding, so that every reported container stays visible. Links to `/containers` redirect to `/bindings` and keep their agent filter, text filter, and sort. A container selected by a former link is not kept.
- Add a Report an issue link to the sidebar foot of the web interface. It opens the GitHub new-issue form in a new tab and sends no data about your site.
- Move binding controls from a side panel to separate full-width screens: `/bindings/new` to bind a container and `/bindings/{id}` to change a binding. A failed create or change stays on the same screen with its message and the values you entered.
- Add explicit row actions and split the long policy and binding screens into tabs. Binding rows have an Edit action and inventory rows an Add binding action, with the container links kept. The policy and binding screens have their actions at the top, and a form submits every field from any tab. Binding screens show a live summary of their decisions. A refused save selects the tab that holds the problem when one tab owns it, and a required field on a hidden tab is shown and focused.
- Delete a policy from its page, through a confirm screen that names the policy and its OpenBao policy. Delete removes both, and is refused while any binding selects the policy, including a binding marked `Not reported` or on an agent that is not approved. The screen lists each binding that blocks the delete. The operational event schema gains the `policy-deleted` operation, recorded with the outcome, policy, and operator. Existing operations and fields are unchanged; a 0.4.x controller refuses a log that holds the new operation.
- A saved policy's page has a **Bindings** tab that lists every binding that selects it, with the container, agent, key, and state, and a link to the binding. A binding whose container is gone stays listed, marked `Not reported`. The header states the number of bindings and agents.
- Rename a policy from its page, including a policy that bindings select. The screen states how many bindings are affected, and each gets a fresh credential with its token lifetime unchanged. The policy keeps its document and bindings and moves to an OpenBao policy for the new name, and the controller removes the old OpenBao policy once every binding has moved, retrying without a client or a restart while that work is pending. A later policy under the old name is a different policy, and a token of the renamed one has no access to it. The operational event schema gains the `policy-renamed` operation and a `new-policy` field. Existing operations and fields are unchanged; a 0.4.x controller refuses a log that holds the new operation.

### Fixes

- Show the label on the New policy button at rest, and keep text readable on
  every link styled as a button.

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
