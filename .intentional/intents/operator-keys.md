---
wyrwood: minor
wyrwood-docs: patch
---

Scripts and programs can now manage policies and bindings over SSH. `wyrwood operator login` presents a key, from a generated file or as one selected key of an SSH agent, and an operator approves it on the new **Operator keys** screen with a grant: allowed agents, allowed policy names, and the actions `read`, `bind`, and `policy-write`. `wyrwood policy put|get|list`, `wyrwood bind`, `wyrwood binding list|get`, and `wyrwood unbind` act inside that grant, and each is safe to repeat. Events name the key as `key:<label>`, and revocation from the web interface takes effect at the key's next request. An operator key has its own SSH subsystem and approval list, so it cannot act as an agent, and an agent key cannot act as an operator. Go programs use the new public package `github.com/wyrd-company/wyrwood/operator`. The controller moves its database to schema 4 when it starts.
