---
wyrwood: minor
wyrwood-docs: patch
---

A container can now be bound by a key that is not `name` before it exists. On
**Add binding**, **Bind by typed key** opens a bind screen where you choose an
approved agent, type a `devcontainer`, `compose`, or `name` key, and, for a key
other than `name`, a directory name. The agent creates that consumer directory
and its sockets right away, so a container created with that key and a mount of
the directory finds working sockets on its first start and reads its secrets
through `vault.sock`. Every container the binding governs uses the directory,
also when its name differs; the token follows the container as for a `name`
binding. A directory name is required when no agent reports a container with the
key. It uses the rule a container name follows, and another binding on the same
agent cannot use it. The binding screen shows it. `wyrwood bind` takes no
directory name and binds as before.

The controller moves its database to schema 5 when it starts, keeping every
binding as it was. A 0.6.1 controller refuses a schema 5 database and leaves it
unchanged, so going back needs the state directory backed up before the
upgrade. A policy set now carries the directory name of such a binding, which a
0.6.1 agent rejects: stop all agents, back up the controller state, upgrade the
controller, then upgrade the agents.
