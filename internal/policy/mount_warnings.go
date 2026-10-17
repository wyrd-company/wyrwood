// ---
// relationships:
//   implements: policy
// ---

package policy

import (
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/hcl"
)

const MountAnalysisUnavailable = "The HCL mount check could not read this policy. Saving is still allowed; OpenBao validates the HCL on save."

// MountWarnings checks whether path stanzas stay inside the expected mount
// roots. This is an advisory scope check, not an OpenBao ACL evaluation.
func MountWarnings(document string, mounts []string) []string {
	var parsed struct {
		Paths []struct {
			Name string `hcl:",key"`
		} `hcl:"path"`
	}
	if hcl.Decode(&parsed, document) != nil {
		return []string{MountAnalysisUnavailable}
	}
	var warnings []string
	seen := map[string]bool{}
	for _, rule := range parsed.Paths {
		if seen[rule.Name] || expectedPath(rule.Name, mounts) {
			continue
		}
		seen[rule.Name] = true
		warnings = append(warnings, fmt.Sprintf("HCL path %q may reach outside the configured mounts. Saving is still allowed; review whether this path is intentional.", rule.Name))
	}
	return warnings
}

func expectedPath(pattern string, mounts []string) bool {
	// OpenBao accepts a leading slash in a path stanza.
	pattern = strings.TrimPrefix(pattern, "/")
	if slices.Contains([]string{"auth/token/lookup-self", "auth/token/renew-self", "auth/token/revoke-self"}, pattern) {
		return true
	}
	for _, mount := range mounts {
		if mount == "" {
			continue
		}
		// Establish the complete literal mount root before any wildcard. A +
		// segment or suffix * below that boundary cannot reach another mount;
		// a pattern such as kv* or auth/+/role/* can.
		if pattern == mount || strings.HasPrefix(pattern, mount+"/") {
			return true
		}
	}
	return false
}
