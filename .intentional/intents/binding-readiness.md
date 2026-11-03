---
wyrwood: minor
wyrwood-docs: patch
---

The Status tab of a binding's screen now shows whether the binding is ready: **Ready**, **Waiting**, **Failed**, or **Unknown**, with the reasons, each consumer directory with its applied access group and listening sockets, and the last login or renewal error. A `name` binding shows its directory before its container exists, so a wrong access group is visible with no look at the host. Readiness comes only from the connected agent, so a removed container cannot read as conforming. The agent reports this in a new `binding-status` message, which an older controller rejects: stop all agents, upgrade the controller, then upgrade the agents.
