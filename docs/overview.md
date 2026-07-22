---
title: Overview
order: 1
docs: true
relationships:
  references:
    - wyrwood
    - linux-per-user-agent-proxy
---

Wyrwood gives Linux containers stable, deliberately limited access to keys held
by a host SSH agent. One unprivileged daemon connects to the user's agent and
publishes a separate SSH-agent-compatible socket for each consumer.

![Wyrwood command-line and terminal demo](assets/demo.gif)

Each consumer socket is an authorization boundary. Its allowlist names exact
SHA-256 public-key fingerprints, so mounting one socket never grants access to
new keys merely because they appear in the host agent. Identity listing and
signing are filtered at request time; agent administration and unknown
extensions are rejected.

Wyrwood addresses two problems with mounting a host agent socket directly:

- **Excess authority** — different containers can receive different key
  allowlists instead of sharing every identity in the host agent.
- **Stale mounts** — containers mount the consumer's parent directory, so a
  replaced socket remains visible without restarting or remounting the
  container.

Private keys never enter Wyrwood. Signing stays inside the configured upstream
agent, including any confirmation or destination restrictions it enforces.
Wyrwood retains only bounded, categorical operational events; it does not store
payloads, signatures, public-key bytes, agent comments, destinations, paths, or
raw protocol messages.

The current release supports Linux hosts, Unix-domain consumer sockets, and a
systemd user service. The command-line interface (CLI) and terminal user
interface (TUI) use the same owner-authenticated local daemon control socket.
