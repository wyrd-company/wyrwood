// ---
// relationships:
//
//	verifies: agent-controller-protocol
//
// ---
package consumer

import (
	"errors"
	"os"
	"os/exec"
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
	g := processGroups(false, 987, []int{987, 1234}, lookup)
	if g.Any || len(g.Groups) != 2 || g.Groups[0].Name != "sample" || g.Groups[1].Name != "" || !g.Allows(987) || !g.Allows(1234) || g.Allows(0) {
		t.Fatalf("groups = %+v", g)
	}
	only := processGroups(false, 987, nil, lookup)
	if len(only.Groups) != 1 || only.Allows(0) || !only.Allows(987) {
		t.Fatalf("only = %+v", only)
	}
	if !processGroups(true, 987, nil, lookup).Allows(42) {
		t.Fatal("privileged process restricted")
	}
}

// TestRootProcessGroupCapabilities exercises actual Linux process credentials.
func TestRootProcessGroupCapabilities(t *testing.T) {
	if os.Getenv("WYRWOOD_GROUP_CAP_HELPER") != "" {
		wantAny := os.Getenv("WYRWOOD_GROUP_CAP_HELPER") == "any"
		report := ProcessGroups()
		if report == nil || report.Any != wantAny || report.Allows(1234) != wantAny || CanAssign(1234) != wantAny {
			t.Fatalf("uid=%d report=%+v CanAssign(1234)=%v want unrestricted=%v", os.Geteuid(), report, CanAssign(1234), wantAny)
		}
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("requires root to change process credentials")
	}
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, want string
		args       []string
	}{
		{"root without CAP_CHOWN", "restricted", []string{"--bounding-set=-chown", "--reuid=0", "--regid=0", "--clear-groups"}},
		{"non-root with CAP_CHOWN", "any", []string{"--reuid=65534", "--regid=65534", "--clear-groups", "--inh-caps=+chown", "--ambient-caps=+chown"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append(tc.args, executable, "-test.run=^TestRootProcessGroupCapabilities$", "-test.v")
			cmd := exec.Command(setpriv, args...)
			cmd.Env = append(os.Environ(), "WYRWOOD_GROUP_CAP_HELPER="+tc.want)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%v\n%s", err, output)
			}
		})
	}
}
