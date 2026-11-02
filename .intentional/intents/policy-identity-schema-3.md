---
wyrwood: major
---

Controller state moves to schema 3, and a policy created under a name used before has a new OpenBao policy, `wyrwood-<name>--<number>`. A token that outlived the earlier policy has no access to the new one, and creating a policy under a used name stays supported. The controller migrates its database at startup: every row stays, existing policies keep `wyrwood-<name>`, existing assignments keep their identity, and live tokens stay valid. A 0.4.x controller refuses a schema 3 database at startup, so back up the state directory before upgrading. Agents and the controller upgrade together, as the stopped rollout requires: a 0.4.x agent rejects the assignment field that names a reused policy.
