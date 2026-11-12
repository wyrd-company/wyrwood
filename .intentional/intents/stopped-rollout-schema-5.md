---
wyrwood: major
wyrwood-docs: patch
---

The controller database moves to schema 5, and the controller sends a binding's `directory` in the policy set. A 0.6.1 controller refuses a schema 5 database at startup and leaves it unchanged, and a 0.6.1 agent closes the session when it receives a binding with a `directory`, so mixed versions do not stay connected. Use the stopped rollout: stop every agent, back up the controller state directory, upgrade the controller, upgrade every agent while it is stopped, then start the agents. Going back needs that backup.
