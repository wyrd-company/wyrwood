// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

func TestPolicyEditorWarnsWithoutAccessGroup(t *testing.T) {
	for _, group := range []string{"", "1000", "0"} {
		output := renderModel(t, "policy", policyPage{AccessGroup: group})
		warns := strings.Contains(output, "No access group:")
		if warns != (group == "") {
			t.Fatalf("group %q warning = %t", group, warns)
		}
	}
	// Empty remains a supported configuration: the warning is advisory.
	document, err := policyFromForm(&http.Request{PostForm: url.Values{"name": {"sample"}, "mount-target": {"/run/wyrwood"}, "enforcement": {"report"}}})
	if err != nil || document.Contract.AccessGroup != nil {
		t.Fatalf("empty group = %#v, %v", document.Contract, err)
	}
}

func TestContractChecksExplainAccessGroupFailure(t *testing.T) {
	group := uint32(1000)
	document := policy.DefaultContract()
	document.AccessGroup = &group
	for _, failed := range []bool{false, true} {
		result := store.ContractResult{Outcome: protocol.OutcomeNonConforming}
		if failed {
			result.FailedItems = []protocol.FailedItem{protocol.FailedAccessGroup}
		}
		checks := contractChecks(document, protocol.Container{}, result)
		page := containersPage{Selected: &containerRow{Bound: true, Checks: checks}}
		output := renderModel(t, "containers", page)
		if strings.Contains(output, "agent user cannot assign group 1000") != failed {
			t.Fatalf("failed=%t: %s", failed, output)
		}
	}
}
