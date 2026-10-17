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

func TestBindingSettingsWarnWithoutAccessGroup(t *testing.T) {
	for _, group := range []string{"", "1000", "0"} {
		request, err := bindingFromForm(&http.Request{PostForm: url.Values{"policies": {"sample"}, "access-group": {group}}})
		if err != nil {
			t.Fatal(err)
		}
		if (request.Settings.AccessGroup == nil) != (group == "") {
			t.Fatalf("group %q = %#v", group, request.Settings)
		}
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
