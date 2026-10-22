// ---
// relationships:
//   implements: composable-policy-bindings
// ---

package policy

import (
	"cmp"
	"github.com/hashicorp/hcl"
	"regexp"
	"slices"
	"strings"
)

// legacyRenewal infers only the capability for the fixed renewal path. It does
// not authorize requests; it only chooses the managed renewal capability.
// Priority follows https://openbao.org/docs/concepts/policies/ and is checked
// against real OpenBao in TestLegacyRenewalMatchesOpenBao.
func legacyRenewal(source string) bool {
	var parsed struct {
		Paths []struct {
			Name         string   `hcl:",key"`
			Capabilities []string `hcl:"capabilities"`
			Policy       string   `hcl:"policy"`
		} `hcl:"path"`
	}
	if hcl.Decode(&parsed, source) != nil {
		return false
	}
	best := ""
	grant, deny := false, false
	for _, rule := range parsed.Paths {
		pattern := strings.TrimPrefix(rule.Name, "/")
		expr := regexp.QuoteMeta(strings.TrimSuffix(pattern, "*"))
		expr = strings.ReplaceAll(expr, `\+`, `[^/]+`)
		if strings.HasSuffix(pattern, "*") {
			expr += ".*"
		}
		if matched, _ := regexp.MatchString("^"+expr+"$", "auth/token/renew-self"); !matched {
			continue
		}
		if best != "" && pathPriority(pattern, best) < 0 {
			continue
		}
		if pattern != best {
			best = pattern
			grant = false
			deny = false
		}
		grant = grant || slices.Contains(rule.Capabilities, "update") || (rule.Policy == "write" || rule.Policy == "sudo")
		deny = deny || slices.Contains(rule.Capabilities, "deny") || rule.Policy == "deny"
	}
	return grant && !deny
}

func pathPriority(a, b string) int {
	first := func(s string) int {
		if i := strings.IndexAny(s, "+*"); i >= 0 {
			return i
		}
		return len(s)
	}
	for _, result := range []int{cmp.Compare(first(a), first(b)), cmp.Compare(strings.Count(b, "*"), strings.Count(a, "*")), cmp.Compare(strings.Count(b, "+"), strings.Count(a, "+")), cmp.Compare(len(a), len(b)), strings.Compare(a, b)} {
		if result != 0 {
			return result
		}
	}
	return 0
}
