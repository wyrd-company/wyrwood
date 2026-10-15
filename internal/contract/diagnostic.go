// ---
// relationships:
//   implements: container-contract
// ---

package contract

import "fmt"

// UnassignableGroup explains a failed access-group check without exposing
// raw system errors.
func UnassignableGroup(group uint32) string {
	return fmt.Sprintf("agent user cannot assign group %d; add the agent user to this host group and restart the agent", group)
}
