---
wyrwood: minor
---

Delete a policy from its page, through a confirm screen that names the policy and its OpenBao policy. Delete removes both, and is refused while any binding selects the policy, including a binding marked `Not reported` or on an agent that is not approved. The screen lists each binding that blocks the delete. The operational event schema gains the `policy-deleted` operation, recorded with the outcome, policy, and operator. Existing operations and fields are unchanged; a 0.4.x controller refuses a log that holds the new operation.
