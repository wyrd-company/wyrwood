// ---
// relationships:
//   implements: composable-policy-bindings
// ---

package policy

import "github.com/hashicorp/hcl"

const RenewalWarning = "No explicit auth/token/renew-self update grant was found. Binding tokens have no default policy; add the token lifecycle HCL so they can renew. This advisory check does not evaluate all OpenBao ACL rules."

// Warnings are advisory rather than an authorization decision. Parsing avoids
// treating commented examples as grants. OpenBao remains the ACL authority.
func Warnings(document string) []string {
	var parsed struct {
		Paths []struct {
			Name         string   `hcl:",key"`
			Capabilities []string `hcl:"capabilities"`
		} `hcl:"path"`
	}
	if hcl.Decode(&parsed, document) != nil {
		return []string{RenewalWarning}
	}
	grant, deny := false, false
	for _, rule := range parsed.Paths {
		if rule.Name != "auth/token/renew-self" {
			continue
		}
		for _, cap := range rule.Capabilities {
			if cap == "update" {
				grant = true
			}
			if cap == "deny" {
				deny = true
			}
		}
	}
	if !grant || deny {
		return []string{RenewalWarning}
	}
	return nil
}
