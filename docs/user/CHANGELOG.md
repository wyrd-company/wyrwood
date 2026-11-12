# Changelog

## 0.1.5

### Fixes

- A container can now be bound by a key that is not `name` before it exists. On
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
- **OpenBao keys** and the policy editor list Transit keys again after a key is imported into the Transit mount. OpenBao then lists an `import/` directory beside the keys, and the controller tried to read it as a key, so both pages showed no Transit key and said OpenBao did not answer. A key that cannot be read no longer empties the list: the page names that key and the failure, such as permission refused, and lists the others. "OpenBao did not answer" now shows only when OpenBao did not answer; a refused list says permission refused.
- When you approve an operator key, you now choose its agents and policies from
  lists of the approved agents and the stored policies, or select all agents or
  all policies. You can still type a name that does not exist yet, such as a
  policy the key will create. Before you approve, the form states what the key can
  and cannot do with each action, on which agents and policies, and that the grant
  cannot be changed after approval. Before, you typed each name, and the form did
  not show what the grant allowed.
- The operations guide tells you how to open the navigation with **Menu** on a phone, and shows the open menu.
- When you rename a policy to its current name, the policy page now says that the name did not change. Before, the page opened with no message. The rename still changes nothing.
- The controller database moves to schema 5, and the controller sends a binding's `directory` in the policy set. A 0.6.1 controller refuses a schema 5 database at startup and leaves it unchanged, and a 0.6.1 agent closes the session when it receives a binding with a `directory`, so mixed versions do not stay connected. Use the stopped rollout: stop every agent, back up the controller state directory, upgrade the controller, upgrade every agent while it is stopped, then start the agents. Going back needs that backup.

## 0.1.4

### Fixes

- The wyrd.foo documentation for this release line now publishes. The product page held more highlights than the publisher accepts, so the 0.6.0 documentation did not publish.
- The controller image now builds. 0.6.0 has no controller image, because the image build did not copy the public `operator` package. Its archives, DEB and RPM packages, and Go module are not affected. To run the controller from the image, use this version.

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
