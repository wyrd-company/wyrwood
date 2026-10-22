// ---
// relationships:
//   implements: composable-policy-bindings
// ---

package policy

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/hashicorp/hcl"
	"github.com/hashicorp/hcl/hcl/ast"
	"github.com/hashicorp/hcl/hcl/printer"
)

// AgentRenewal reports the resolved choice delivered to the agent.
func (e Effective) AgentRenewal() bool {
	if e.OpenBao.AgentTokenRenewal != nil {
		return *e.OpenBao.AgentTokenRenewal
	}
	// Field-free assignments retain source provenance. Infer each policy's
	// choice before applying the same grant union used by current composition.
	if len(e.Sources) > 0 {
		for _, source := range e.Sources {
			if legacyRenewal(source.HCL) {
				return true
			}
		}
		return false
	}
	return legacyRenewal(e.OpenBao.Policy)
}

// PreviewHCL shows managed lifecycle grants for field-free stored assignments
// without changing the durable assignment or its identity.
func (e Effective) PreviewHCL() string {
	if e.OpenBao.AgentTokenRenewal != nil {
		return e.OpenBao.Policy
	}
	if len(e.Sources) == 0 {
		return WorkloadHCL(e.OpenBao.Policy) + "\n" + LifecycleHCL(e.AgentRenewal())
	}
	var result strings.Builder
	for _, source := range e.Sources {
		fmt.Fprintf(&result, "# Policy %s (revision %d)\n%s\n%s\n", source.Name, source.Revision, WorkloadHCL(source.HCL), LifecycleHCL(legacyRenewal(source.HCL)))
	}
	return result.String()
}

// AgentRenewal preserves the renewal choice of documents without the setting.
func (p Policy) AgentRenewal() bool {
	if p.OpenBao.AgentTokenRenewal != nil {
		return *p.OpenBao.AgentTokenRenewal
	}
	return legacyRenewal(p.OpenBao.Policy)
}

// PublishedHCL is the workload source plus Wyrwood's managed lifecycle grants.
func (p Policy) PublishedHCL() string {
	return WorkloadHCL(p.OpenBao.Policy) + "\n" + LifecycleHCL(p.AgentRenewal())
}

// LifecycleHCL contains the fixed lifecycle capabilities managed by Wyrwood.
func LifecycleHCL(renew bool) string {
	result := "path \"auth/token/lookup-self\" { capabilities = [\"read\"] }\n"
	if renew {
		result += "path \"auth/token/renew-self\" { capabilities = [\"update\"] }\n"
	} else {
		// An exact empty rule overrides broader grants without a deny that
		// would defeat another selected policy's renewal update capability.
		result += "path \"auth/token/renew-self\" { capabilities = [] }\n"
	}
	return result + "path \"auth/token/revoke-self\" { capabilities = [\"update\"] }\n"
}

func lifecyclePath(path string) bool {
	switch strings.TrimPrefix(path, "/") {
	case "auth/token/lookup-self", "auth/token/renew-self", "auth/token/revoke-self":
		return true
	}
	return false
}

// WorkloadHCL removes exact lifecycle stanzas from the compiled document.
// The authored source remains intact; all other OpenBao constructs are retained.
func WorkloadHCL(source string) string {
	parsed, err := hcl.Parse(source)
	if err != nil {
		return source
	} // OpenBao remains the validity authority.
	list, ok := parsed.Node.(*ast.ObjectList)
	if !ok {
		return source
	}
	jsonSource := strings.HasPrefix(strings.TrimSpace(source), "{")
	var kept []*ast.ObjectItem
	type span struct{ start, end int }
	var removed []span
	for _, item := range list.Items {
		if len(item.Keys) == 2 && item.Keys[0].Token.Value() == "path" {
			name, _ := item.Keys[1].Token.Value().(string)
			if lifecyclePath(name) {
				if object, ok := item.Val.(*ast.ObjectType); ok {
					removed = append(removed, span{item.Pos().Offset, object.Rbrace.Offset + 1})
				}
				continue
			}
		}
		kept = append(kept, item)
	}
	if jsonSource {
		list.Items = kept
		var output bytes.Buffer
		if printer.Fprint(&output, parsed) != nil {
			return source
		}
		return output.String()
	}
	for i := len(removed) - 1; i >= 0; i-- {
		source = source[:removed[i].start] + source[removed[i].end:]
	}
	return source
}
