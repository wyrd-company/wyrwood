// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"bytes"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

func TestPolicyEditorWarnsWithoutAccessGroup(t *testing.T) {
	pages, err := parsePages()
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"", "1000", "0"} {
		var output bytes.Buffer
		if err := pages["policy"].ExecuteTemplate(&output, "layout", policyPage{AccessGroup: group}); err != nil {
			t.Fatal(err)
		}
		warns := strings.Contains(output.String(), "No access group:")
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
		var output bytes.Buffer
		pages, err := parsePages()
		if err != nil {
			t.Fatal(err)
		}
		page := containersPage{Selected: &containerRow{Bound: true, Checks: checks}}
		if err := pages["containers"].ExecuteTemplate(&output, "layout", page); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), "agent user cannot assign group 1000") != failed {
			t.Fatalf("failed=%t: %s", failed, output.String())
		}
	}
}
