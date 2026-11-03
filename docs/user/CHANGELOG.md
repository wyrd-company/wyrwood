# Changelog

## 0.1.3

### Fixes

- The Status tab of a binding's screen now shows whether the binding is ready: **Ready**, **Waiting**, **Failed**, or **Unknown**, with the reasons, each consumer directory with its applied access group and listening sockets, and the last login or renewal error. A `name` binding shows its directory before its container exists, so a wrong access group is visible with no look at the host. Readiness comes only from the connected agent, so a removed container cannot read as conforming. The agent reports this in a new `binding-status` message, which an older controller rejects: stop all agents, upgrade the controller, then upgrade the agents.
- A `name` binding now has its consumer directory and sockets before its container exists, so the container's first start finds working sockets. They stay when the container is removed and return after an agent restart, also when Docker is not running yet. The agent holds a token only while a container has that name: it gets one when the container is first observed, also in the `created` state, and revokes it when the container is removed. Until then, requests to `vault.sock` answer with status 503 and the error `no-token`. After an upgrade, a stored `Not reported` name binding gets its directory and sockets on its agent. Bindings on other keys behave as before.
- The agent now starts a bound container after a host reboot, once its sockets are ready. Docker's own start fails on the missing consumer directory and does not retry. The agent acts only on an exited container with a restart policy whose recorded error names that directory as missing. The Engine proxy now permits container start on every host, so a compromised agent can start any stopped container. Stop, remove, and create still need `allow-recreate`. A `-v` bind does not get this recovery; use `--mount type=bind`.
- Scripts and programs can now manage policies and bindings over SSH. `wyrwood operator login` presents a key, from a generated file or as one selected key of an SSH agent, and an operator approves it on the new **Operator keys** screen with a grant: allowed agents, allowed policy names, and the actions `read`, `bind`, and `policy-write`. `wyrwood policy put|get|list`, `wyrwood bind`, `wyrwood binding list|get`, and `wyrwood unbind` act inside that grant, and each is safe to repeat. Events name the key as `key:<label>`, and revocation from the web interface takes effect at the key's next request. An operator key has its own SSH subsystem and approval list, so it cannot act as an agent, and an agent key cannot act as an operator. Go programs use the new public package `github.com/wyrd-company/wyrwood/operator`. The controller moves its database to schema 4 when it starts.
- One policy can now apply to many bindings with a different path for each. Write `{{binding.name}}` in a path stanza, for example `path "kv/data/sample/{{binding.slug}}"`, and each binding sets its own value on the binding screen. The preview shows the path with the value. A value holds only letters, digits, underscores, and hyphens, so it cannot reach another binding's path. A binding with no value for a placeholder is refused when you save it, and so is a policy edit that would leave one without a value. OpenBao evaluates these paths through identity templating, so this needs no new OpenBao policy for each container and no new controller permission.
- The controller database moves to schema 4, and agents send a new `binding-status` message. A 0.5.x controller refuses a schema 4 database at startup and closes the session of an agent that sends the message, so mixed versions do not stay connected. Use the stopped rollout: stop every agent, back up the controller state directory, upgrade the controller, upgrade every agent while it is stopped, then start the agents. Going back needs that backup.

## 0.1.2

### Fixes

- Describe the Report an issue link in the operations guide.
- Describe the separate bind and binding screens in the getting started and operations guides, with new screenshots.
- Describe the Bindings page and the Add binding screen in the getting started and operations guides, with new screenshots.
- Describe the row actions and the tabs on the policy and binding screens in the guides, with new screenshots.
- Describe deleting a policy, what blocks it, and reusing its name in the operations guide, with two new screenshots. Describe the backup, schema 3, and the way back in the install guide.
- Describe the Bindings tab of the policy page in the getting started and operations guides, with a new screenshot.
- Describe renaming a policy, what happens to its bindings and tokens, and how a pending transition finishes in the operations guide, with a new screenshot.

## 0.1.1

### Fixes

- Show effective controller settings in a read-only web admin page with operator authorization and an explicit projection that excludes credentials and credential-file paths.
- Run the shared host agent inside the controller with opt-in local-agent configuration, retaining standalone enrollment, approval, Engine isolation, and local status commands. Join recreate workers and drain admitted operator requests before releasing durable state during shutdown.
- Publish the user documentation from docs/user in the wyrd.foo v2 format, with a products map, structured install entries, highlights, the web interface screenshots as product media, and the product logo and favicon.
- Choose binding access groups from the running agent’s reported process groups,
  reject known unassignable selections on the server, and explain unknown reports,
  host restarts, owner-only access, and container application group retention.
- Lead the user guide with web workflows, refresh real interface screenshots, and check screenshot freshness and local documentation links with a repeatable demo recorder.
