---
wyrwood: patch
---

Document a dedicated OpenBao namespace as the supported controller deployment, so that a compromised controller or operator can grant nothing outside Wyrwood's namespace. The controller's own policy and AppRole are named outside the `wyrwood-` prefix, and binding AppRoles accept only their own managed policy.
