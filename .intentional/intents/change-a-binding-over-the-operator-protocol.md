---
wyrwood: minor
wyrwood-docs: patch
---

A program can now change an existing binding's policies and settings, including
the values its policies read, over the operator protocol, with `ChangeBinding`
in the `operator` package. The change applies at once, as an edit in the web
interface does: the container's old token is revoked, the container reads with
the new selection without a restart, and its consumer directory and sockets stay
in place. The change names the binding's revision: when another change came
first, it fails with `ErrRevisionDiffers` and changes nothing. It needs the Bind
action and a grant that covers the binding and every policy it selects. Before,
a program had to unbind and bind again, which took the container's sockets away
in between. The event history now lists each policy of a binding change as the
binding held it before and after, and the operator key approval form says that
Bind also changes bindings.
