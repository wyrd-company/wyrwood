// ---
// relationships:
//   verifies:
//     - controller
//     - operator-interface
// ---

package controller

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/operator"
)

func sampleName(value string) operator.Key { return operator.Key{Kind: operator.KeyName, Value: value} }

// grantEvents returns the grant-changed events of a key, oldest first.
func grantEvents(harness *harness, fingerprint string) []events.Event {
	var found []events.Event
	for _, event := range harness.controller.Events().Recent(1000) {
		if event.Operation == events.OperationOperatorKeyGrantChanged && event.Fingerprint == fingerprint {
			found = append(found, event)
		}
	}
	return found
}

// A key gains a policy with one edit, and the client that the key opened
// before the edit binds it on its next request: no new key, no new label, no
// reconnection, and no revocation.
func TestAGrantEditReachesAnOpenSessionOnItsNextRequest(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	harness.approveAgent(t, "sample-host")
	harness.savePolicy(t, "teal")
	harness.savePolicy(t, "amber")
	before := operator.Grant{Agents: []string{"sample-host"}, Policies: []string{"teal"}, Actions: []operator.Action{operator.ActionRead, operator.ActionBind}}
	client, key := harness.approvedOperator(t, "menagerie", before)
	fingerprint := gossh.FingerprintSHA256(key.PublicKey())
	approved, err := harness.controller.Store().OperatorKey(ctx, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	request := operator.BindRequest{Agent: "sample-host", Key: sampleName("sample-app"), Policies: []string{"amber", "teal"}}
	if _, err := client.Bind(ctx, request); !errors.Is(err, operator.ErrOutsideGrant) {
		t.Fatalf("Bind() before the edit = %v; want outside the grant", err)
	}

	after := before
	after.Policies = []string{"teal", "amber"}
	if err := harness.controller.ChangeOperatorKeyGrant(ctx, fingerprint, before, after, "sample-approver"); err != nil {
		t.Fatal(err)
	}

	bound, err := client.Bind(ctx, request)
	if err != nil {
		t.Fatalf("Bind() on the open session after the edit = %v", err)
	}
	if !slices.Equal(bound.Policies, []string{"amber", "teal"}) {
		t.Fatalf("bound policies = %v", bound.Policies)
	}
	identity, err := client.Whoami(ctx)
	if err != nil || identity.Label != "menagerie" || identity.Fingerprint != fingerprint || !store.SameGrant(identity.Grant, after) {
		t.Fatalf("Whoami() = %+v, %v", identity, err)
	}
	edited, err := harness.controller.Store().OperatorKey(ctx, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	approved.Grant, edited.Grant = operator.Grant{}, operator.Grant{}
	// LastUsed moves with each session the key opens.
	approved.LastUsed, edited.LastUsed = time.Time{}, time.Time{}
	if !reflect.DeepEqual(edited, approved) {
		t.Fatalf("the edit changed the key: %+v; want %+v", edited, approved)
	}
}

// An edit records one event per entry of the old and the new grant, with the
// key, the operator, and one time.
func TestAGrantEditRecordsTheOldAndNewGrant(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	before := operator.Grant{Agents: []string{"host-a"}, Policies: []string{"teal", "amber"}, Actions: []operator.Action{operator.ActionRead}}
	_, key := harness.approvedOperator(t, "sample-key", before)
	fingerprint := gossh.FingerprintSHA256(key.PublicKey())
	after := operator.Grant{Agents: []string{operator.AllNames}, Policies: []string{"teal", "cyan"}, Actions: []operator.Action{operator.ActionRead, operator.ActionPolicyWrite}}
	if err := harness.controller.ChangeOperatorKeyGrant(ctx, fingerprint, before, after, "sample-approver"); err != nil {
		t.Fatal(err)
	}
	recorded := grantEvents(harness, fingerprint)
	if len(recorded) == 0 {
		t.Fatal("the edit has no event")
	}
	type entry struct{ before, after string }
	got := map[string][]entry{}
	for _, event := range recorded {
		if !event.Time.Equal(recorded[0].Time) || event.Operator != "sample-approver" || event.Outcome != events.OutcomeOK {
			t.Fatalf("event = %+v", event)
		}
		switch {
		case event.Agent != "" || event.NewAgent != "":
			got["agents"] = append(got["agents"], entry{event.Agent, event.NewAgent})
		case event.Policy != "" || event.NewPolicy != "":
			got["policies"] = append(got["policies"], entry{event.Policy, event.NewPolicy})
		case event.Action != "" || event.NewAction != "":
			got["actions"] = append(got["actions"], entry{string(event.Action), string(event.NewAction)})
		default:
			got["bounds"] = append(got["bounds"], entry{})
		}
	}
	// The edit begins and ends with an event that names no entry, so that a
	// reader can tell whether it has every event of the edit.
	bound := events.Event{Time: recorded[0].Time, Operation: events.OperationOperatorKeyGrantChanged, Outcome: events.OutcomeOK,
		Fingerprint: fingerprint, Operator: "sample-approver"}
	if recorded[0] != bound || recorded[len(recorded)-1] != bound {
		t.Fatalf("the edit's first and last events = %+v, %+v; want %+v", recorded[0], recorded[len(recorded)-1], bound)
	}
	want := map[string][]entry{
		"agents":   {{"", "*"}, {"host-a", ""}},
		"policies": {{"amber", ""}, {"", "cyan"}, {"teal", "teal"}},
		"actions":  {{"", "policy-write"}, {"read", "read"}},
		"bounds":   {{}, {}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("recorded entries = %v; want %v", got, want)
	}

	// Saving the grant the key holds changes nothing and records nothing.
	if err := harness.controller.ChangeOperatorKeyGrant(ctx, fingerprint, after, after, "sample-approver"); err != nil {
		t.Fatal(err)
	}
	if again := grantEvents(harness, fingerprint); len(again) != len(recorded) {
		t.Fatalf("an unchanged grant recorded %d events", len(again)-len(recorded))
	}
}

func TestAGrantEditIsRefusedAndChangesNothing(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	grant := operator.Grant{Agents: []string{"host-a"}, Policies: []string{"teal"}, Actions: []operator.Action{operator.ActionRead}}
	_, key := harness.approvedOperator(t, "sample-key", grant)
	fingerprint := gossh.FingerprintSHA256(key.PublicKey())
	wider := grant
	wider.Policies = []string{"teal", "amber"}
	stale := grant
	stale.Policies = []string{"other"}
	for name, edit := range map[string]struct {
		fingerprint string
		from, to    operator.Grant
		message     string
	}{
		"no action":        {fingerprint, grant, operator.Grant{Policies: []string{"teal"}}, "select at least one action"},
		"invalid name":     {fingerprint, grant, operator.Grant{Policies: []string{"Not Valid"}, Actions: grant.Actions}, "is invalid"},
		"all and names":    {fingerprint, grant, operator.Grant{Policies: []string{"*", "teal"}, Actions: grant.Actions}, "only"},
		"stale":            {fingerprint, stale, wider, "changed after you opened it"},
		"unknown key":      {"SHA256:unknown", grant, wider, "no approved key"},
		"unknown action":   {fingerprint, grant, operator.Grant{Actions: []operator.Action{"admin"}}, "not supported"},
		"too many entries": {fingerprint, grant, operator.Grant{Agents: slices.Repeat([]string{"host-a"}, 257), Actions: grant.Actions}, "more than 256"},
	} {
		t.Run(name, func(t *testing.T) {
			err := harness.controller.ChangeOperatorKeyGrant(ctx, edit.fingerprint, edit.from, edit.to, "sample-approver")
			if err == nil || !strings.Contains(err.Error(), edit.message) {
				t.Fatalf("ChangeOperatorKeyGrant() = %v; want %q", err, edit.message)
			}
		})
	}
	if stored, err := harness.controller.Store().OperatorKey(ctx, fingerprint); err != nil || !store.SameGrant(stored.Grant, grant) {
		t.Fatalf("a refused edit changed the grant: %+v, %v", stored, err)
	}
	if recorded := grantEvents(harness, fingerprint); len(recorded) != 0 {
		t.Fatalf("a refused edit recorded %v", recorded)
	}
	if err := harness.controller.RevokeOperatorKey(ctx, fingerprint, "sample-approver"); err != nil {
		t.Fatal(err)
	}
	if err := harness.controller.ChangeOperatorKeyGrant(ctx, fingerprint, grant, wider, "sample-approver"); err == nil {
		t.Fatal("a revoked key's grant was edited")
	}
}

// Choosing keys from a policy changes only their policy lists. A key's actions
// then apply to the policy, also a key without Bind, and a key with all
// policies is never rewritten.
func TestAPolicyGivesAndTakesItselfFromKeys(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	harness.savePolicy(t, "teal")
	harness.savePolicy(t, "amber")
	reader := operator.Grant{Agents: []string{"host-a"}, Policies: []string{"teal"}, Actions: []operator.Action{operator.ActionRead}}
	readerClient, readerKey := harness.approvedOperator(t, "reader", reader)
	writer := operator.Grant{Agents: []string{}, Policies: []string{"amber", "teal"}, Actions: []operator.Action{operator.ActionPolicyWrite}}
	_, writerKey := harness.approvedOperator(t, "writer", writer)
	_, wideKey := harness.approvedOperator(t, "wide", fullGrant)
	readerPrint, writerPrint := gossh.FingerprintSHA256(readerKey.PublicKey()), gossh.FingerprintSHA256(writerKey.PublicKey())
	widePrint := gossh.FingerprintSHA256(wideKey.PublicKey())
	if _, err := readerClient.GetPolicy(ctx, "amber"); !errors.Is(err, operator.ErrOutsideGrant) {
		t.Fatalf("PolicyGet() before = %v", err)
	}

	if err := harness.controller.ChangePolicyOperatorKeys(ctx, "amber", []string{readerPrint, widePrint}, []string{writerPrint}, "sample-approver"); err != nil {
		t.Fatal(err)
	}
	grantOf := func(fingerprint string) operator.Grant {
		t.Helper()
		key, err := harness.controller.Store().OperatorKey(ctx, fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		return key.Grant
	}
	if got, want := grantOf(readerPrint), (operator.Grant{Agents: reader.Agents, Policies: []string{"teal", "amber"}, Actions: reader.Actions}); !store.SameGrant(got, want) {
		t.Fatalf("reader grant = %+v; want %+v", got, want)
	}
	if got, want := grantOf(writerPrint), (operator.Grant{Agents: writer.Agents, Policies: []string{"teal"}, Actions: writer.Actions}); !store.SameGrant(got, want) {
		t.Fatalf("writer grant = %+v; want %+v", got, want)
	}
	if got := grantOf(widePrint); !store.SameGrant(got, fullGrant) {
		t.Fatalf("a key with all policies was rewritten: %+v", got)
	}
	if _, err := readerClient.GetPolicy(ctx, "amber"); err != nil {
		t.Fatalf("Read does not reach the added policy: %v", err)
	}
	for fingerprint, changed := range map[string]bool{readerPrint: true, writerPrint: true, widePrint: false} {
		if got := len(grantEvents(harness, fingerprint)) > 0; got != changed {
			t.Fatalf("events for %s = %v; want %v", fingerprint, got, changed)
		}
	}

	if err := harness.controller.ChangePolicyOperatorKeys(ctx, "amber", nil, []string{widePrint}, "sample-approver"); err == nil || !strings.Contains(err.Error(), "holds all policies") {
		t.Fatalf("removing a policy from a key with all policies = %v", err)
	}
	if err := harness.controller.ChangePolicyOperatorKeys(ctx, "amber", nil, []string{readerPrint, "SHA256:unknown"}, "sample-approver"); err == nil {
		t.Fatal("a change with an unknown key was accepted")
	}
	if got := grantOf(readerPrint); !slices.Contains(got.Policies, "amber") {
		t.Fatalf("a refused change applied in part: %+v", got)
	}
	if got := grantOf(widePrint); !store.SameGrant(got, fullGrant) {
		t.Fatalf("a refused change rewrote a key with all policies: %+v", got)
	}
}

// The events package carries the grant actions as its own closed vocabulary.
func TestEventActionsAreTheGrantActions(t *testing.T) {
	var got []string
	for _, action := range events.Actions {
		got = append(got, string(action))
	}
	var want []string
	for _, action := range operator.Actions {
		want = append(want, string(action))
	}
	if !slices.Equal(got, want) {
		t.Fatalf("event actions = %v; grant actions = %v", got, want)
	}
}

// Only the web interface changes a grant: no operator request reaches the code
// that writes one, so that a key cannot widen its own grant.
func TestOnlyTheWebInterfaceChangesAGrant(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	writers := map[string]bool{"ChangeOperatorKeyGrant": true, "ChangePolicyOperatorKeys": true, "ChangeOperatorKeyGrants": true, "changeGrants": true}
	allowed := map[string]bool{"internal/controller/operator_keys.go": true}
	callers := map[string]bool{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		relative, _ := filepath.Rel(root, path)
		ast.Inspect(file, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				if selector, ok := call.Fun.(*ast.SelectorExpr); ok && writers[selector.Sel.Name] {
					callers[filepath.ToSlash(relative)] = true
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for caller := range callers {
		if !allowed[caller] && !strings.HasPrefix(caller, "internal/web/") {
			t.Errorf("%s changes an operator key grant outside the web interface", caller)
		}
	}
	if !callers["internal/controller/operator_keys.go"] {
		t.Fatal("the scan found no caller at all")
	}
}

// The longest names and operator subject a grant change can hold are recorded
// whole: an entry too long for one event is recorded as its old side and its
// new side, and both bounds are there.
func TestAGrantChangeWithTheLongestNamesIsRecordedWhole(t *testing.T) {
	ctx := context.Background()
	harness := startHarness(t)
	longAgent := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	otherAgent := strings.Repeat("e", 63) + "." + strings.Repeat("f", 63) + "." + strings.Repeat("g", 63) + "." + strings.Repeat("h", 61)
	longPolicy := "p" + strings.Repeat("0", 63)
	before := operator.Grant{Agents: []string{longAgent, otherAgent}, Policies: []string{longPolicy}, Actions: []operator.Action{operator.ActionRead}}
	_, key := harness.approvedOperator(t, "sample-key", before)
	fingerprint := gossh.FingerprintSHA256(key.PublicKey())
	after := operator.Grant{Agents: []string{longAgent}, Policies: []string{longPolicy, "teal"}, Actions: operator.Actions}
	// JSON escapes < as six bytes, the longest form a subject's bytes can take.
	by := strings.Repeat("<", 255)
	if err := harness.controller.ChangeOperatorKeyGrant(ctx, fingerprint, before, after, by); err != nil {
		t.Fatal(err)
	}
	recorded := grantEvents(harness, fingerprint)
	bound := events.Event{Time: recorded[0].Time, Operation: events.OperationOperatorKeyGrantChanged, Outcome: events.OutcomeOK, Fingerprint: fingerprint, Operator: by}
	if len(recorded) < 2 || recorded[0] != bound || recorded[len(recorded)-1] != bound {
		t.Fatalf("the change is not bounded: %+v", recorded)
	}
	var oldAgents, newAgents, oldPolicies, newPolicies, oldActions, newActions []string
	gather := func(list *[]string, name string) {
		if name != "" && !slices.Contains(*list, name) {
			*list = append(*list, name)
		}
	}
	split := false
	for _, event := range recorded[1 : len(recorded)-1] {
		if event == bound {
			t.Fatalf("a bound inside the change: %+v", recorded)
		}
		gather(&oldAgents, event.Agent)
		gather(&newAgents, event.NewAgent)
		gather(&oldPolicies, event.Policy)
		gather(&newPolicies, event.NewPolicy)
		gather(&oldActions, string(event.Action))
		gather(&newActions, string(event.NewAction))
		split = split || (event.Agent == longAgent && event.NewAgent == "")
	}
	actions := func(list []operator.Action) []string {
		names := []string{}
		for _, action := range list {
			names = append(names, string(action))
		}
		return names
	}
	for name, pair := range map[string][2][]string{
		"old agents": {oldAgents, before.Agents}, "new agents": {newAgents, after.Agents},
		"old policies": {oldPolicies, before.Policies}, "new policies": {newPolicies, after.Policies},
		"old actions": {oldActions, actions(before.Actions)}, "new actions": {newActions, actions(after.Actions)},
	} {
		if !slices.Equal(slices.Sorted(slices.Values(pair[0])), slices.Sorted(slices.Values(pair[1]))) {
			t.Fatalf("%s = %v; want %v", name, pair[0], pair[1])
		}
	}
	if !split {
		t.Fatal("the kept long agent fit one event, so this test no longer reaches the split")
	}
}

// The closing bound follows only the opening bound and every entry. An entry
// that cannot be appended, whole or as its two sides, leaves the change
// without its closing bound, so no reader counts it as whole.
func TestAGrantChangeIsClosedOnlyWhenEveryEntryIsRecorded(t *testing.T) {
	base := events.Event{Time: time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC), Operation: events.OperationOperatorKeyGrantChanged,
		Outcome: events.OutcomeOK, Fingerprint: "SHA256:" + strings.Repeat("A", 43), Operator: "sample-approver"}
	kept, added := base, base
	kept.Agent, kept.NewAgent = "host-a", "host-a"
	added.Policy, added.NewPolicy = "", "teal"
	entries := []events.Event{kept, added}
	refused := errors.New("refused")
	for name, test := range map[string]struct {
		refuse    func(events.Event) bool
		wantError bool
		want      []events.Event
	}{
		"every entry fits": {refuse: func(events.Event) bool { return false },
			want: []events.Event{base, kept, added, base}},
		"an entry fits only as its two sides": {refuse: func(event events.Event) bool { return event == kept },
			want: []events.Event{base, {Time: base.Time, Operation: base.Operation, Outcome: base.Outcome, Fingerprint: base.Fingerprint, Operator: base.Operator, Agent: "host-a"},
				{Time: base.Time, Operation: base.Operation, Outcome: base.Outcome, Fingerprint: base.Fingerprint, Operator: base.Operator, NewAgent: "host-a"}, added, base}},
		"an entry with both sides is refused": {refuse: func(event events.Event) bool { return event.Agent == "host-a" || event.NewAgent == "host-a" },
			wantError: true, want: []events.Event{base}},
		"an entry's new side is refused": {refuse: func(event events.Event) bool {
			return event == kept || (event.NewAgent == "host-a" && event.Agent == "")
		},
			wantError: true, want: []events.Event{base, {Time: base.Time, Operation: base.Operation, Outcome: base.Outcome, Fingerprint: base.Fingerprint, Operator: base.Operator, Agent: "host-a"}}},
		"an entry's old side is refused": {refuse: func(event events.Event) bool {
			return event == kept || (event.Agent == "host-a" && event.NewAgent == "")
		},
			wantError: true, want: []events.Event{base}},
		"an entry with one side is refused": {refuse: func(event events.Event) bool { return event == added },
			wantError: true, want: []events.Event{base, kept}},
		"the opening bound is refused": {refuse: func(event events.Event) bool { return event == base },
			wantError: true, want: nil},
	} {
		t.Run(name, func(t *testing.T) {
			var appended []events.Event
			err := recordGrantEvents(func(event events.Event) error {
				if test.refuse(event) {
					return refused
				}
				appended = append(appended, event)
				return nil
			}, base, entries)
			if (err != nil) != test.wantError || !reflect.DeepEqual(appended, test.want) {
				t.Fatalf("recordGrantEvents() = %v, appended %+v; want error %t, %+v", err, appended, test.wantError, test.want)
			}
		})
	}
}
