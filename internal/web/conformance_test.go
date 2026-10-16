// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

func TestContractChecksShowSocketFailures(t *testing.T) {
	group := uint32(1000)
	for _, accessGroup := range []*uint32{nil, &group} {
		document := policy.DefaultContract()
		document.AccessGroup = accessGroup
		for _, outcome := range []protocol.Outcome{"", protocol.OutcomeConforming, protocol.OutcomeNonConforming} {
			result := store.ContractResult{Outcome: outcome}
			wantMark := "OK"
			if outcome == "" {
				wantMark = "UNKNOWN"
			}
			if outcome == protocol.OutcomeNonConforming {
				result.FailedItems = []protocol.FailedItem{protocol.FailedConsumerDirectory, protocol.FailedSocketAccess}
				wantMark = "MISSING"
			}
			found := 0
			checks := contractChecks(document, protocol.Container{}, result)
			for _, item := range checks {
				if item.Label == "consumer directory and sockets" || strings.HasPrefix(item.Label, "socket access (") {
					found++
					if item.Mark != wantMark {
						t.Errorf("%s: %s, want %s", item.Label, item.Mark, wantMark)
					}
				}
			}
			if found != 2 {
				t.Fatalf("socket checks = %d, want 2", found)
			}
			output := renderModel(t, "containers", containersPage{Selected: &containerRow{Bound: true, Checks: checks}})
			if !strings.Contains(output, "socket access (") || (accessGroup != nil && !strings.Contains(output, "verifiable member of access group 1000")) {
				t.Fatalf("socket access diagnostic missing: %s", output)
			}
		}
	}
}
