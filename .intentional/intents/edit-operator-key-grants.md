---
wyrwood: minor
wyrwood-docs: patch
---

An operator can now edit an approved operator key's grant. **Edit grant** beside
the key on **Operator keys** opens its agents, policies, and actions, with **What
this key can do** updating as you change them. **Validate** checks the grant
without saving it, and **Save** applies it. The key keeps its fingerprint and
label, and its next request uses the new grant, also on a connection that is
already open, so letting a tool bind one more policy is one edit: no new key,
configuration change, restart, or revocation. A save made after another edit of
the same key is refused and changes nothing.

A policy's new **Operator keys** tab, on **Create policy** and **Edit policy**,
lists each approved key with its actions. Checking a key gives it the policy,
and clearing it takes the policy away, when the policy is saved. The key's
actions do not change, so its Read, Bind, and Policy write then reach the
policy. A key that holds all policies shows checked and is not changed there.

Each edit is recorded with who made it, when, and the old and new grant: the
event history has one `operator-key-grant-changed` event per entry of the grant,
and **Events** shows the edit as one row whose **Old and new grant** compares
them. Only the web interface changes a grant; a key cannot change its own. The
approval form no longer says that a grant cannot be changed.

The operational event schema gains the `operator-key-grant-changed` operation
and the `new-agent`, `action`, and `new-action` fields. Existing operations and
fields are unchanged; a 0.7.0 controller refuses an event log that holds the
new operation, so going back after a grant edit needs the event log from before
the upgrade.
