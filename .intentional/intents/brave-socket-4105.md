---
wyrwood: minor
wyrwood-docs: patch
---

A `name` binding now has its consumer directory and sockets before its container exists, so the container's first start finds working sockets. They stay when the container is removed and return after an agent restart, also when Docker is not running yet. The agent holds a token only while a container has that name: it gets one when the container is first observed, also in the `created` state, and revokes it when the container is removed. Until then, requests to `vault.sock` answer with status 503 and the error `no-token`. After an upgrade, a stored `Not reported` name binding gets its directory and sockets on its agent. Bindings on other keys behave as before.
