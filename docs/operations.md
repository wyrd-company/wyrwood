---
title: Operations and command reference
order: 5
docs: true
relationships:
  references:
    - command-line-interface
    - operational-events
    - web-interface
---

Wyrwood provides human-readable output for interactive use and closed,
versioned JSON for automation.

```bash
sudo wyrwood agent status
sudo wyrwood agent containers
sudo wyrwood agent events --limit 50
sudo wyrwood agent status --output json
```

Successful output goes to standard output. Categorical errors go to standard
error. Automation can distinguish usage, login, daemon, controller, and
fingerprint failures by exit status without parsing error text.

## Web interface

The controller's web interface shows agents with pending approvals,
containers per agent with binding and conformance state, policies, OpenBao
keys under the managed mounts, and events. Bind it to loopback and place it
behind a reverse proxy that terminates TLS.

![OpenBao keys page with Transit keys and SSH-engine roles](assets/web-keys.png)

Operators sign in through the site's OpenID Connect provider. The controller
admits an account only when its groups claim names a group listed under
`oidc.allowed-groups`, and checks membership at every sign-in. Remove someone
from the group in the provider to revoke their access at their next sign-in;
their open session ends at the session time-to-live or when an operator ends
it from **Security**. While the provider is unreachable the interface cannot
be used, but agents keep serving containers.

## Operational events

The agent and the controller each retain a bounded event history. Agent
events cover container observation, bindings, contract checks and recreates,
token login and renewal, vault requests by mount category, and SSH identity
listing, signing, and certificate issuance. Controller events cover operator
sign-in and sign-out, agent approval, sessions, policy saves, bindings, and
credential issuance, and name the operator who acted. Events contain no
tokens, secret values, request bodies, paths, signatures, or raw upstream
errors.

![Controller events, newest first](assets/web-events.png)

## Commands

| Command | Purpose |
| --- | --- |
| `wyrwood controller serve` | Run the controller. |
| `wyrwood controller host-key` | Print the controller's SSH host-key fingerprint. |
| `wyrwood agent login <url>` | Generate the agent key, accept the controller fingerprint, and request approval. |
| `wyrwood agent daemon` | Run the agent directly. |
| `wyrwood agent status` | Inspect agent, controller session, and binding health. |
| `wyrwood agent containers` | List observed containers with binding, conformance, and token state. |
| `wyrwood agent events` | Read the newest bounded operational events. |
| `wyrwood agent service install\|remove\|start\|stop\|status` | Manage the system unit. |
| `wyrwood version` | Print the executable version. |

Run `wyrwood help` for the top-level grammar or append `--help` to a command
for its options.
