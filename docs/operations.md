---
title: Operations and command reference
order: 5
docs: true
relationships:
  references:
    - command-line-interface
    - operational-events
    - terminal-interface
---

Wyrwood provides human-readable output for interactive use and closed,
versioned JSON for automation.

```bash
wyrwood status
wyrwood events --limit 50
wyrwood status --output json
wyrwood service status --output json
```

Successful output goes to standard output. Categorical, actionable errors go to
standard error. Automation can distinguish usage, initialization, daemon,
configuration, apply, upstream, stale-revision, durability, and missing-consumer
failures by exit status without parsing internal error text.

## Terminal interface

Run `wyrwood tui` from an interactive terminal to manage the same daemon through
a keyboard-only interface. It exposes the dashboard, upstream keys, consumer
details, consumer creation, timeouts, health, and recent events.

```bash
wyrwood tui
```

Saved edits remain visibly `UNAPPLIED` until the explicit Apply action succeeds.
Dirty edits require confirmation before discard or exit. Press `?` to expand
the help for the current view.

## Operational events

The daemon retains a bounded per-user event history for reconciliation,
connections, identity listing, signing, and session binding. Events include
categorical outcomes, latency, consumer identifiers, and a key fingerprint only
when the operation needs one. They exclude signing payloads, signatures,
public-key bytes, agent comments, filesystem paths, destinations, and raw
errors.

## Commands

| Command | Purpose |
| --- | --- |
| `wyrwood init` | Create the initial per-user configuration from `SSH_AUTH_SOCK`. |
| `wyrwood daemon` | Run the per-user daemon directly. |
| `wyrwood service install\|remove\|start\|stop\|status` | Manage login startup through the systemd user manager. |
| `wyrwood keys` | List upstream identities as fingerprints and display labels. |
| `wyrwood status` | Inspect daemon, upstream, and consumer health. |
| `wyrwood events` | Read the newest bounded operational events. |
| `wyrwood configuration show` | Read the complete durable configuration and revision. |
| `wyrwood configuration set-upstream` | Replace the durable upstream socket path. |
| `wyrwood configuration set-timeouts` | Replace the complete timeout set. |
| `wyrwood consumer put` | Create or completely replace one consumer. |
| `wyrwood consumer retire` | Remove one consumer from durable configuration. |
| `wyrwood apply` | Validate and atomically apply durable configuration. |
| `wyrwood tui` | Open the terminal management interface. |
| `wyrwood version` | Print the executable version. |

Run `wyrwood help` for the top-level grammar or append `--help` to a management
command for its exact options.
