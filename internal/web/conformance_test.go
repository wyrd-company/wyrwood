// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"testing"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

func TestContractChecksShowSocketFailures(t *testing.T) {
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
		for _, item := range contractChecks(policy.DefaultContract(), protocol.Container{}, result) {
			if item.Label == "consumer directory and sockets" || item.Label == "socket access (container user must be root or the agent uid)" {
				found++
				if item.Mark != wantMark {
					t.Errorf("%s: %s, want %s", item.Label, item.Mark, wantMark)
				}
			}
		}
		if found != 2 {
			t.Fatalf("socket checks = %d, want 2", found)
		}
	}
}
