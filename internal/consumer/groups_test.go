// ---
// relationships:
//
//	verifies: agent-controller-protocol
//
// ---
package consumer

import (
	"errors"
	"os/user"
	"testing"
)

func TestProcessGroupsUsesRunningMembershipAndOptionalNames(t *testing.T) {
	lookup := func(id string) (*user.Group, error) {
		if id == "987" {
			return &user.Group{Name: "sample"}, nil
		}
		return nil, errors.New("no name")
	}
	g := processGroups(999, 987, []int{987, 1234}, lookup)
	if g.Any || len(g.Groups) != 2 || g.Groups[0].Name != "sample" || g.Groups[1].Name != "" || !g.Allows(987) || !g.Allows(1234) || g.Allows(0) {
		t.Fatalf("groups = %+v", g)
	}
	only := processGroups(999, 987, nil, lookup)
	if len(only.Groups) != 1 || only.Allows(0) || !only.Allows(987) {
		t.Fatalf("only = %+v", only)
	}
	if !processGroups(0, 987, nil, lookup).Allows(42) {
		t.Fatal("privileged process restricted")
	}
}
