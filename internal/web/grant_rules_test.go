// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/policy"
	operatorclient "github.com/wyrd-company/wyrwood/operator"
)

// grantNameCasesFile holds the server's answers for the approval summary's
// copies of the grant rules. The frontend test reads the same file.
const grantNameCasesFile = "testdata/grant-name-cases.json"

type grantNameCase struct {
	Name  string `json:"name"`
	Valid bool   `json:"valid"`
}

type grantNameCases struct {
	MaximumEntries int             `json:"maximumEntries"`
	Agents         []grantNameCase `json:"agents"`
	Policies       []grantNameCase `json:"policies"`
}

func grantRuleAnswers(t *testing.T) grantNameCases {
	t.Helper()
	label := strings.Repeat("a", 63)
	longest := strings.Join([]string{label, label, label, strings.Repeat("b", 61)}, ".")
	agentNames := []string{"agent-a", "a", "A-1.b-2", "1host", "host-", "-host", "host..name", "host.name.", ".host",
		"bad/name", "under_score", "space name", "é", "", label, label + "a", longest, longest + "c", "host.-sub", "*x"}
	policyNames := []string{"policy-x", "x", "policy-x2", "Policy", "policy--x", "policy-", "-policy", "1policy", "policy_x",
		"bad/name", "é", "", strings.Repeat("p", 64), strings.Repeat("p", 65), "p-" + strings.Repeat("q", 62), "*x"}
	answers := grantNameCases{Agents: []grantNameCase{}, Policies: []grantNameCase{}}
	for _, name := range agentNames {
		answers.Agents = append(answers.Agents, grantNameCase{Name: name, Valid: controller.ValidAgentName(name)})
	}
	for _, name := range policyNames {
		answers.Policies = append(answers.Policies, grantNameCase{Name: name, Valid: policy.ValidName(name)})
	}
	// The entry limit is the largest list Grant.Validate accepts.
	for size := 1; size <= 4096; size++ {
		grant := operatorclient.Grant{Agents: make([]string, size), Policies: []string{"*"}, Actions: []operatorclient.Action{operatorclient.ActionRead}}
		for index := range grant.Agents {
			grant.Agents[index] = "agent-a"
		}
		if grant.Validate(controller.ValidAgentName, policy.ValidName) != nil {
			answers.MaximumEntries = size - 1
			break
		}
	}
	if answers.MaximumEntries == 0 {
		t.Fatal("Grant.Validate accepted every list size up to 4096")
	}
	return answers
}

// TestGrantNameCasesAreTheServerAnswers keeps the frontend's copy of the grant
// rules tied to the server: the file must hold the server's own answers. Set
// WYRWOOD_UPDATE_GRANT_NAME_CASES=1 to write them.
func TestGrantNameCasesAreTheServerAnswers(t *testing.T) {
	answers := grantRuleAnswers(t)
	if os.Getenv("WYRWOOD_UPDATE_GRANT_NAME_CASES") == "1" {
		encoded, err := json.MarshalIndent(answers, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(grantNameCasesFile, append(encoded, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	content, err := os.ReadFile(grantNameCasesFile)
	if err != nil {
		t.Fatal(err)
	}
	var recorded grantNameCases
	if err := json.Unmarshal(content, &recorded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(recorded, answers) {
		t.Fatalf("%s differs from the server's answers; recorded %+v, server %+v", grantNameCasesFile, recorded, answers)
	}
	valid, invalid := 0, 0
	for _, item := range append(append([]grantNameCase{}, answers.Agents...), answers.Policies...) {
		if item.Valid {
			valid++
		} else {
			invalid++
		}
	}
	if valid == 0 || invalid == 0 {
		t.Fatalf("the cases hold %d valid and %d invalid names; both kinds are needed", valid, invalid)
	}
}
