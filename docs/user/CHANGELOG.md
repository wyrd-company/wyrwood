# Changelog

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
