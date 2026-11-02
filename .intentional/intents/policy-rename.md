---
wyrwood: minor
---

Rename a policy from its page, including a policy that bindings select. The screen states how many bindings are affected, and each gets a fresh credential with its token lifetime unchanged. The policy keeps its document and bindings and moves to an OpenBao policy for the new name, and the controller removes the old OpenBao policy once every binding has moved, retrying without a client or a restart while that work is pending. A later policy under the old name is a different policy, and a token of the renamed one has no access to it. The operational event schema gains the `policy-renamed` operation and a `new-policy` field. Existing operations and fields are unchanged; a 0.4.x controller refuses a log that holds the new operation.
