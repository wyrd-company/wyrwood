# Changelog

## 0.1.1

### Fixes

- Show effective controller settings in a read-only web admin page with operator authorization and an explicit projection that excludes credentials and credential-file paths.
- Run the shared host agent inside the controller with opt-in local-agent configuration, retaining standalone enrollment, approval, Engine isolation, and local status commands. Join recreate workers and drain admitted operator requests before releasing durable state during shutdown.
- Publish the user documentation from docs/user in the wyrd.foo v2 format, with a products map, structured install entries, highlights, the web interface screenshots as product media, and the product logo and favicon.
- Choose binding access groups from the running agent’s reported process groups,
  reject known unassignable selections on the server, and explain unknown reports,
  host restarts, owner-only access, and container application group retention.
- Lead the user guide with web workflows, refresh real interface screenshots, and check screenshot freshness and local documentation links with a repeatable demo recorder.
