// ---
// relationships:
//   implements: composable-policy-bindings
// ---

package policy

import (
	"cmp"
	"regexp"
	"slices"
	"strings"

	"github.com/hashicorp/hcl"
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
		segments := strings.Split(pattern, "/")
		for i, segment := range segments {
			if segment == "+" {
				segments[i] = `[^/]+`
			} else if i == len(segments)-1 && strings.HasSuffix(segment, "*") {
				segments[i] = regexp.QuoteMeta(strings.TrimSuffix(segment, "*")) + ".*"
			} else {
				segments[i] = regexp.QuoteMeta(segment)
			}
		}
		expr := strings.Join(segments, "/")
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
	wildcards := func(s string) (int, int, int) {
		first, count, glob, offset := len(s), 0, 0, 0
		for _, segment := range strings.Split(s, "/") {
			if segment == "+" {
				first = min(first, offset)
				count++
			}
			offset += len(segment) + 1
		}
		if strings.HasSuffix(s, "*") {
			first = min(first, len(s)-1)
			glob = 1
		}
		return first, count, glob
	}
	firstA, countA, globA := wildcards(a)
	firstB, countB, globB := wildcards(b)
	for _, result := range []int{cmp.Compare(firstA, firstB), cmp.Compare(globB, globA), cmp.Compare(countB, countA), cmp.Compare(len(a), len(b)), strings.Compare(a, b)} {
		if result != 0 {
			return result
		}
	}
	return 0
}
