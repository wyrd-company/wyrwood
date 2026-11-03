---
wyrwood: major
wyrwood-docs: patch
---

The controller database moves to schema 4, and agents send a new `binding-status` message. A 0.5.x controller refuses a schema 4 database at startup and closes the session of an agent that sends the message, so mixed versions do not stay connected. Use the stopped rollout: stop every agent, back up the controller state directory, upgrade the controller, upgrade every agent while it is stopped, then start the agents. Going back needs that backup.
