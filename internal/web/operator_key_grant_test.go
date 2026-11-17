// ---
// relationships:
//   verifies:
//     - web-interface
//     - operator-interface
// ---

package web

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/web/oidctest"
	operatorclient "github.com/wyrd-company/wyrwood/operator"
)

// The renderer unescapes attribute values, so the JSON keeps its quotes.
var previousPattern = regexp.MustCompile(`name="previous" value="(\{.*?\})"`)

// grantEditFixture runs a controller with an approved agent, the policies
// teal and amber in OpenBao, a signed-in browser, and an operator client whose
// key holds grant and has a session open.
func grantEditFixture(t *testing.T, grant operatorclient.Grant) (*harness, *http.Client, *operatorclient.Client, string) {
	t.Helper()
	ctx := context.Background()
	harness := startHarness(t, time.Hour)
	browserClient := browser(t)
	harness.signIn(t, browserClient, operator, oidctest.TamperNone)
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := harness.controller.Store().RecordKey(ctx, "sample-host", "sample-host", "ssh-ed25519 AAAA-sample-host", now); err != nil {
		t.Fatal(err)
	}
	if _, err := harness.controller.Store().DecideAgent(ctx, "sample-host", store.AgentApproved, "operator", now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"teal", "amber"} {
		if _, err := harness.controller.SavePolicy(ctx, policy.New(name, samplePolicyHCL), "operator"); err != nil {
			t.Fatal(err)
		}
	}
	client, fingerprint := approveOperatorKey(t, harness, "menagerie", grant)
	return harness, browserClient, client, fingerprint
}

// approveOperatorKey approves a new key with grant and returns a client with a
// session open, and the key's fingerprint.
func approveOperatorKey(t *testing.T, harness *harness, label string, grant operatorclient.Grant) (*operatorclient.Client, string) {
	t.Helper()
	ctx := context.Background()
	key := mustKey(t)
	settings := operatorclient.Config{URL: harness.controller.URL, Signer: key, HostKey: harness.controller.Fingerprint, Label: label, Timeout: 5 * time.Second}
	if _, err := operatorclient.Login(ctx, settings, nil); err != nil {
		t.Fatal(err)
	}
	fingerprint := gossh.FingerprintSHA256(key.PublicKey())
	if err := harness.controller.ApproveOperatorKey(ctx, fingerprint, label, grant, "approver"); err != nil {
		t.Fatal(err)
	}
	client, err := operatorclient.Dial(ctx, settings)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, fingerprint
}

// Adding a policy to a key is one edit in the web interface. The client the
// key opened before the edit binds the policy on its next request, with no new
// key, configuration change, restart, or revocation.
func TestAKeyGainsAPolicyWithOneEditInTheWebInterface(t *testing.T) {
	ctx := context.Background()
	before := operatorclient.Grant{Agents: []string{"sample-host"}, Policies: []string{"teal"}, Actions: []operatorclient.Action{operatorclient.ActionRead, operatorclient.ActionBind}}
	harness, browserClient, client, fingerprint := grantEditFixture(t, before)
	approved, err := harness.controller.Store().OperatorKey(ctx, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	request := operatorclient.BindRequest{Agent: "sample-host", Key: operatorclient.Key{Kind: operatorclient.KeyName, Value: "workspace"}, Policies: []string{"amber", "teal"}}
	if _, err := client.Bind(ctx, request); !errors.Is(err, operatorclient.ErrOutsideGrant) {
		t.Fatalf("Bind() before the edit = %v; want outside the grant", err)
	}

	list := get(t, browserClient, harness.site.URL+"/operator-keys")
	editURL := "/operator-keys/grant?" + url.Values{"fingerprint": {fingerprint}}.Encode()
	if !strings.Contains(list.body, `href="`+editURL+`"`) {
		t.Fatalf("the approved key has no Edit grant link: %s", list.body)
	}
	editor := get(t, browserClient, harness.site.URL+editURL)
	for _, want := range []string{"Edit grant", "menagerie", fingerprint, "What this key can do", ">Validate<", ">Save<", `checked="" value="teal"`} {
		if !strings.Contains(editor.body, want) {
			t.Fatalf("the grant editor has no %s: %s", want, editor.body)
		}
	}
	for _, absent := range []string{"Review", "Cancel", "cannot be changed"} {
		if strings.Contains(editor.body, absent) {
			t.Fatalf("the grant editor holds %q: %s", absent, editor.body)
		}
	}
	previous := previousPattern.FindStringSubmatch(editor.body)
	if previous == nil {
		t.Fatalf("the grant editor holds no previous grant: %s", editor.body)
	}
	saved := post(t, browserClient, harness.site.URL+"/operator-keys/grant", url.Values{
		"csrf": {csrf(t, editor.body)}, "fingerprint": {fingerprint}, "previous": {previous[1]},
		"agents": {"sample-host", ""}, "policies": {"teal", "amber", ""}, "actions": {"read", "bind"},
	})
	if !strings.Contains(saved.body, "Grant saved.") || !strings.Contains(saved.body, `checked="" value="amber"`) {
		t.Fatalf("save = %s", saved.body)
	}

	bound, err := client.Bind(ctx, request)
	if err != nil {
		t.Fatalf("Bind() on the open session after the edit = %v", err)
	}
	if !slices.Equal(bound.Policies, []string{"amber", "teal"}) {
		t.Fatalf("bound policies = %v", bound.Policies)
	}
	identity, err := client.Whoami(ctx)
	if err != nil || identity.Label != "menagerie" || identity.Fingerprint != fingerprint {
		t.Fatalf("Whoami() = %+v, %v", identity, err)
	}
	edited, err := harness.controller.Store().OperatorKey(ctx, fingerprint)
	if err != nil || edited.Label != approved.Label || edited.PublicKey != approved.PublicKey || edited.State != store.OperatorKeyApproved ||
		!edited.DecidedAt.Equal(approved.DecidedAt) || edited.DecidedBy != approved.DecidedBy {
		t.Fatalf("the edit changed the key: %+v; was %+v", edited, approved)
	}
	if want := []string{"teal", "amber"}; !slices.Equal(edited.Grant.Policies, want) {
		t.Fatalf("policies = %v; want %v", edited.Grant.Policies, want)
	}
	subject := ""
	for _, event := range harness.controller.Events().Recent(1000) {
		if event.Operation == events.OperationOperatorKeyGrantChanged && event.Fingerprint == fingerprint {
			subject = event.Operator
		}
	}
	if subject == "" || strings.HasPrefix(subject, "key:") {
		t.Fatalf("the edit is recorded with operator %q; want the operator who signed in", subject)
	}
}

// A save that starts from a grant the key no longer holds changes nothing, and
// the editor keeps the edit and says why.
func TestAStaleGrantEditIsRefused(t *testing.T) {
	ctx := context.Background()
	before := operatorclient.Grant{Agents: []string{"sample-host"}, Policies: []string{"teal"}, Actions: []operatorclient.Action{operatorclient.ActionRead}}
	harness, browserClient, _, fingerprint := grantEditFixture(t, before)
	editor := get(t, browserClient, harness.site.URL+"/operator-keys/grant?"+url.Values{"fingerprint": {fingerprint}}.Encode())
	previous := previousPattern.FindStringSubmatch(editor.body)
	if previous == nil {
		t.Fatalf("the grant editor holds no previous grant: %s", editor.body)
	}
	other := before
	other.Actions = []operatorclient.Action{operatorclient.ActionRead, operatorclient.ActionBind}
	if err := harness.controller.ChangeOperatorKeyGrant(ctx, fingerprint, before, other, "other-operator"); err != nil {
		t.Fatal(err)
	}
	refused := post(t, browserClient, harness.site.URL+"/operator-keys/grant", url.Values{
		"csrf": {csrf(t, editor.body)}, "fingerprint": {fingerprint}, "previous": {previous[1]},
		"agents": {"sample-host", ""}, "policies": {"teal", "amber", ""}, "actions": {"read"},
	})
	if refused.status != http.StatusUnprocessableEntity || !strings.Contains(refused.body, "changed after you opened it") ||
		!strings.Contains(refused.body, `checked="" value="amber"`) {
		t.Fatalf("stale save = %d %s", refused.status, refused.body)
	}
	if stored, err := harness.controller.Store().OperatorKey(ctx, fingerprint); err != nil || !store.SameGrant(stored.Grant, other) {
		t.Fatalf("a stale save changed the grant: %+v, %v", stored, err)
	}
	forged := post(t, browserClient, harness.site.URL+"/operator-keys/grant", url.Values{
		"fingerprint": {fingerprint}, "previous": {previous[1]}, "agents": {"*"}, "policies": {"*"}, "actions": {"read", "bind", "policy-write"},
	})
	if forged.status != http.StatusForbidden {
		t.Fatalf("a save with no CSRF token = %d", forged.status)
	}
	unreadable := post(t, browserClient, harness.site.URL+"/operator-keys/grant", url.Values{
		"csrf": {csrf(t, editor.body)}, "fingerprint": {fingerprint}, "previous": {`{"agents":`},
		"agents": {"*"}, "policies": {"*"}, "actions": {"read"},
	})
	if unreadable.status != http.StatusUnprocessableEntity || !strings.Contains(unreadable.body, "does not say which grant it started from") {
		t.Fatalf("save with no readable previous grant = %d %s", unreadable.status, unreadable.body)
	}
	if stored, err := harness.controller.Store().OperatorKey(ctx, fingerprint); err != nil || !store.SameGrant(stored.Grant, other) {
		t.Fatalf("a save with no readable previous grant changed the grant: %+v, %v", stored, err)
	}
	if missing := get(t, browserClient, harness.site.URL+"/operator-keys/grant?fingerprint=SHA256%3Aunknown"); !strings.Contains(missing.body, "No approved key has this fingerprint") {
		t.Fatalf("editor of an unknown key = %s", missing.body)
	}
}

// A policy's Operator keys tab gives the policy to the keys checked there and
// takes it from the keys cleared there. A key keeps its actions, which then
// reach the policy, also a key without Bind. A key that holds all policies is
// never rewritten.
func TestAPolicyChoosesItsOperatorKeys(t *testing.T) {
	ctx := context.Background()
	binder := operatorclient.Grant{Agents: []string{"sample-host"}, Policies: []string{"teal"}, Actions: []operatorclient.Action{operatorclient.ActionRead, operatorclient.ActionBind}}
	harness, browserClient, binderClient, binderPrint := grantEditFixture(t, binder)
	reader := operatorclient.Grant{Agents: []string{}, Policies: []string{}, Actions: []operatorclient.Action{operatorclient.ActionRead}}
	readerClient, readerPrint := approveOperatorKey(t, harness, "inventory-reader", reader)
	everything := operatorclient.Grant{Agents: []string{"*"}, Policies: []string{"*"}, Actions: []operatorclient.Action{operatorclient.ActionRead}}
	_, adminPrint := approveOperatorKey(t, harness, "fleet-admin", everything)
	grantOf := func(fingerprint string) operatorclient.Grant {
		t.Helper()
		key, err := harness.controller.Store().OperatorKey(ctx, fingerprint)
		if err != nil {
			t.Fatal(err)
		}
		return key.Grant
	}

	editor := get(t, browserClient, harness.site.URL+"/policies/edit?name=amber")
	for _, want := range []string{"Operator keys", "menagerie", "Read, Bind", "inventory-reader", "fleet-admin", "Read · All policies",
		`name="operator-keys-listed" value="` + binderPrint + `"`, `name="operator-keys-listed" value="` + readerPrint + `"`,
		`disabled="" name="operator-keys" checked="" value="` + adminPrint + `"`} {
		if !strings.Contains(editor.body, want) {
			t.Fatalf("the policy editor has no %s: %s", want, editor.body)
		}
	}
	if strings.Contains(editor.body, `name="operator-keys-held"`) || strings.Contains(editor.body, `name="operator-keys-listed" value="`+adminPrint+`"`) {
		t.Fatalf("the policy editor lists a key it must not change: %s", editor.body)
	}
	token := csrf(t, editor.body)
	save := func(fields url.Values) page {
		t.Helper()
		form := url.Values{"csrf": {token}, "name": {"amber"}, "hcl": {samplePolicyHCL}, "mount-target": {"/run/wyrwood"}}
		for name, values := range fields {
			form[name] = values
		}
		return post(t, browserClient, harness.site.URL+"/policies", form)
	}

	saved := save(url.Values{"operator-keys-listed": {binderPrint, readerPrint}, "operator-keys": {binderPrint, readerPrint}})
	if !strings.Contains(saved.body, "Policy saved") {
		t.Fatalf("save = %s", saved.body)
	}
	if got := grantOf(binderPrint); !slices.Equal(got.Policies, []string{"teal", "amber"}) || !slices.Equal(got.Actions, binder.Actions) {
		t.Fatalf("menagerie grant = %+v", got)
	}
	if got := grantOf(readerPrint); !slices.Equal(got.Policies, []string{"amber"}) || !slices.Equal(got.Actions, reader.Actions) {
		t.Fatalf("inventory-reader grant = %+v", got)
	}
	if got := grantOf(adminPrint); !store.SameGrant(got, everything) {
		t.Fatalf("fleet-admin grant = %+v", got)
	}
	if _, err := readerClient.GetPolicy(ctx, "amber"); err != nil {
		t.Fatalf("Read does not reach the policy given from its screen: %v", err)
	}
	request := operatorclient.BindRequest{Agent: "sample-host", Key: operatorclient.Key{Kind: operatorclient.KeyName, Value: "amber-app"}, Policies: []string{"amber"}}
	if _, err := binderClient.Bind(ctx, request); err != nil {
		t.Fatalf("Bind does not reach the policy given from its screen: %v", err)
	}
	if !strings.Contains(saved.body, `name="operator-keys-held" value="`+binderPrint+`"`) {
		t.Fatalf("the saved policy does not show menagerie as holding it: %s", saved.body)
	}

	// Clearing a box takes the policy away; a key whose box did not change
	// keeps what it has, also when another edit gave it the policy meanwhile.
	cleared := save(url.Values{"operator-keys-listed": {readerPrint}, "operator-keys-held": {readerPrint}})
	if !strings.Contains(cleared.body, "Policy saved") {
		t.Fatalf("save = %s", cleared.body)
	}
	if got := grantOf(readerPrint); len(got.Policies) != 0 {
		t.Fatalf("inventory-reader kept the policy: %+v", got)
	}
	if got := grantOf(binderPrint); !slices.Contains(got.Policies, "amber") {
		t.Fatalf("a key the form did not list lost the policy: %+v", got)
	}

	// A key's grant editor gives it the policy after the policy's screen opened
	// with the key's box clear. Saving that screen with the box still clear
	// leaves the key as the other edit made it.
	readerGrant := grantOf(readerPrint)
	gained := readerGrant
	gained.Policies = []string{"amber"}
	if err := harness.controller.ChangeOperatorKeyGrant(ctx, readerPrint, readerGrant, gained, "other-operator"); err != nil {
		t.Fatal(err)
	}
	if unchanged := save(url.Values{"operator-keys-listed": {readerPrint}}); !strings.Contains(unchanged.body, "Policy saved") {
		t.Fatalf("save = %s", unchanged.body)
	}
	if got := grantOf(readerPrint); !slices.Equal(got.Policies, []string{"amber"}) {
		t.Fatalf("a box that did not change took the policy away: %+v", got)
	}
	if err := harness.controller.ChangeOperatorKeyGrant(ctx, readerPrint, gained, readerGrant, "other-operator"); err != nil {
		t.Fatal(err)
	}

	forged := save(url.Values{"operator-keys-listed": {adminPrint, readerPrint}, "operator-keys-held": {adminPrint}, "operator-keys": {readerPrint}})
	if forged.status != http.StatusUnprocessableEntity || !strings.Contains(forged.body, "Policy saved. Its operator keys did not change: operator key fleet-admin holds all policies") {
		t.Fatalf("taking the policy from a key with all policies = %d %s", forged.status, forged.body)
	}
	if got := grantOf(adminPrint); !store.SameGrant(got, everything) {
		t.Fatalf("a key with all policies was rewritten: %+v", got)
	}
	if got := grantOf(readerPrint); len(got.Policies) != 0 {
		t.Fatalf("a refused change applied in part: %+v", got)
	}

	created := post(t, browserClient, harness.site.URL+"/policies", url.Values{"csrf": {token}, "new": {"yes"}, "name": {"cyan"}, "hcl": {samplePolicyHCL}, "mount-target": {"/run/wyrwood"},
		"operator-keys-listed": {binderPrint, readerPrint}, "operator-keys": {readerPrint}})
	if !strings.Contains(created.body, "Policy saved") {
		t.Fatalf("create = %s", created.body)
	}
	if got := grantOf(readerPrint); !slices.Equal(got.Policies, []string{"cyan"}) {
		t.Fatalf("inventory-reader after create = %+v", got)
	}
	if got := grantOf(binderPrint); slices.Contains(got.Policies, "cyan") {
		t.Fatalf("an unchecked key was given the new policy: %+v", got)
	}
}

// The Events screen shows one grant edit as one row with the old and the new
// grant, also when other events came between the edit's events.
func TestAGrantEditIsOneEventRow(t *testing.T) {
	ctx := context.Background()
	before := operatorclient.Grant{Agents: []string{"sample-host"}, Policies: []string{"teal", "amber"}, Actions: []operatorclient.Action{operatorclient.ActionRead}}
	harness, browserClient, _, fingerprint := grantEditFixture(t, before)
	after := operatorclient.Grant{Agents: []string{"*"}, Policies: []string{"teal", "cyan"}, Actions: []operatorclient.Action{operatorclient.ActionRead, operatorclient.ActionPolicyWrite}}
	if err := harness.controller.ChangeOperatorKeyGrant(ctx, fingerprint, before, after, "editor-subject"); err != nil {
		t.Fatal(err)
	}
	// A second edit of the same key is a row of its own.
	if err := harness.controller.ChangeOperatorKeyGrant(ctx, fingerprint, after, before, "editor-subject"); err != nil {
		t.Fatal(err)
	}
	// Move one event of the second edit behind an unrelated event, as a
	// concurrent writer could.
	var edit []events.Event
	recent := harness.controller.Events().Recent(1000)
	for index := len(recent) - 1; index >= 0; index-- {
		event := recent[index]
		if event.Operation == events.OperationOperatorKeyGrantChanged && (len(edit) == 0 || event.Time.Equal(edit[0].Time)) {
			edit = append(edit, event)
		}
	}
	if len(edit) < 2 {
		t.Fatalf("the edit recorded %d events", len(edit))
	}
	if err := harness.controller.Events().Append(events.Event{Time: edit[0].Time, Operation: events.OperationPolicySaved, Outcome: events.OutcomeOK, Policy: "teal", Operator: "editor-subject"}); err != nil {
		t.Fatal(err)
	}
	if err := harness.controller.Events().Append(edit[0]); err != nil {
		t.Fatal(err)
	}

	response, err := browserClient.Get(harness.site.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	match := pageDataPattern.FindSubmatch(body)
	if match == nil {
		t.Fatalf("no page data in %s", body)
	}
	var payload struct{ Data eventsPage }
	if err := json.Unmarshal(match[1], &payload); err != nil {
		t.Fatal(err)
	}
	var rows []eventRow
	for _, row := range payload.Data.Events {
		if row.Operation == string(events.OperationOperatorKeyGrantChanged) {
			rows = append(rows, row)
		}
	}
	if len(rows) != 2 || rows[0].Grant == nil || rows[1].Grant == nil {
		t.Fatalf("grant edit rows = %+v; want one row for each edit", rows)
	}
	if !rows[0].Time.After(rows[1].Time) || rows[0].Grant.Rows[0] != (grantChangeRow{Name: "Agents", Before: "All", After: "sample-host", Changed: true}) {
		t.Fatalf("the second edit is not the newest row: %+v", rows)
	}
	row := rows[1]
	editURL := "/operator-keys/grant?" + url.Values{"fingerprint": {fingerprint}}.Encode()
	if row.Subject != "key:menagerie" || row.Operator != "editor-subject" || row.Grant.Fingerprint != fingerprint || row.Grant.EditURL != editURL {
		t.Fatalf("row = %+v, change = %+v", row, row.Grant)
	}
	want := []grantChangeRow{
		{Name: "Agents", Before: "sample-host", After: "All", Changed: true},
		{Name: "Policies", Before: "amber, teal", After: "cyan, teal", Changed: true},
		{Name: "Read", Before: "Allowed", After: "Allowed"},
		{Name: "Bind", Before: "Denied", After: "Denied"},
		{Name: "Policy write", Before: "Denied", After: "Allowed", Changed: true},
	}
	if !row.Grant.Complete || !reflect.DeepEqual(row.Grant.Rows, want) {
		t.Fatalf("rows = %+v; want %+v", row.Grant.Rows, want)
	}
	page := renderedPage(t, body)
	for _, want := range []string{"Old and new grant", "<th scope=\"row\">Policies</th><td>amber, teal</td><td class=\"changed\">cyan, teal<strong> · Changed</strong>", "View current key grant"} {
		if !strings.Contains(page, want) {
			t.Fatalf("the Events screen has no %s: %s", want, page)
		}
	}
}

// The edit at the last displayed row shows its whole old and new grant, also
// when an unrelated event came between its events and the newer events fill
// every other row. This is review round 1's reproducer; it picks the edit's
// last entry by its action, since an edit's events end with one that names
// no entry.
func TestAGrantEditAtTheRowLimitIsWhole(t *testing.T) {
	ctx := context.Background()
	before := operatorclient.Grant{Agents: []string{"sample-host"}, Policies: []string{"teal"}, Actions: []operatorclient.Action{operatorclient.ActionRead}}
	harness, browserClient, _, fingerprint := grantEditFixture(t, before)
	after := before
	after.Policies = []string{"teal", "amber"}
	if err := harness.controller.ChangeOperatorKeyGrant(ctx, fingerprint, before, after, "review-operator"); err != nil {
		t.Fatal(err)
	}
	var entry events.Event
	for _, event := range harness.controller.Events().Recent(1000) {
		if event.Operation == events.OperationOperatorKeyGrantChanged && event.Fingerprint == fingerprint && event.Action != events.ActionNone {
			entry = event
		}
	}
	if entry.Action != events.ActionRead {
		t.Fatalf("expected final action entry, got %+v", entry)
	}
	appendEvent := func(event events.Event) {
		t.Helper()
		if err := harness.controller.Events().Append(event); err != nil {
			t.Fatal(err)
		}
	}
	unrelated := events.Event{Time: time.Now().UTC(), Operation: events.OperationPolicySaved, Outcome: events.OutcomeOK, Policy: "teal", Operator: "review-operator"}
	// As in TestAGrantEditIsOneEventRow, move one entry behind an unrelated
	// event; duplicates disappear in the grant's set projection.
	appendEvent(unrelated)
	appendEvent(entry)
	for range maximumEventRows - 1 {
		appendEvent(unrelated)
	}
	payload := eventsPayload(t, browserClient, harness.site.URL+"/events")
	if len(payload.Events) != maximumEventRows {
		t.Fatalf("rows = %d; want %d", len(payload.Events), maximumEventRows)
	}
	row := payload.Events[maximumEventRows-1]
	if row.Grant == nil {
		t.Fatalf("the last displayed row is not the grant edit: %+v", row)
	}
	want := []grantChangeRow{
		{Name: "Agents", Before: "sample-host", After: "sample-host"},
		{Name: "Policies", Before: "teal", After: "amber, teal", Changed: true},
		{Name: "Read", Before: "Allowed", After: "Allowed"},
		{Name: "Bind", Before: "Denied", After: "Denied"},
		{Name: "Policy write", Before: "Denied", After: "Denied"},
	}
	if !row.Grant.Complete || !reflect.DeepEqual(row.Grant.Rows, want) {
		t.Fatalf("incomplete history presented as complete old/new grant: %+v", row.Grant)
	}
}

// eventsPayload reads the page data of the Events screen.
func eventsPayload(t *testing.T, client *http.Client, target string) eventsPage {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	match := pageDataPattern.FindSubmatch(body)
	if match == nil {
		t.Fatalf("no page data in %s", body)
	}
	var payload struct{ Data eventsPage }
	if err := json.Unmarshal(match[1], &payload); err != nil {
		t.Fatal(err)
	}
	return payload.Data
}

// Retention drops the oldest events, so an edit can lose its first events
// while its newest stay. Its row then says that the edit is not whole and
// shows no old or new grant.
func TestACutOffGrantEditShowsNoGrant(t *testing.T) {
	ctx := context.Background()
	before := operatorclient.Grant{Agents: []string{"sample-host"}, Policies: []string{"teal"}, Actions: []operatorclient.Action{operatorclient.ActionRead}}
	harness, browserClient, _, fingerprint := grantEditFixture(t, before)
	after := before
	after.Policies = []string{"teal", "amber"}
	if err := harness.controller.ChangeOperatorKeyGrant(ctx, fingerprint, before, after, "review-operator"); err != nil {
		t.Fatal(err)
	}
	var edit []events.Event
	for _, event := range harness.controller.Events().Recent(1000) {
		if event.Operation == events.OperationOperatorKeyGrantChanged {
			edit = append(edit, event)
		}
	}
	// Record the same edit again under another time without its first two
	// events, the bound and the agent entry, as retention would leave it.
	cut := time.Now().UTC().Add(time.Second)
	for _, event := range edit[2:] {
		event.Time = cut
		if err := harness.controller.Events().Append(event); err != nil {
			t.Fatal(err)
		}
	}
	page := eventsPayload(t, browserClient, harness.site.URL+"/events")
	var changes []*grantChange
	for _, row := range page.Events {
		if row.Grant != nil {
			changes = append(changes, row.Grant)
		}
	}
	if len(changes) != 2 {
		t.Fatalf("grant edit rows = %d; want 2", len(changes))
	}
	if changes[0].Complete || len(changes[0].Rows) != 0 {
		t.Fatalf("a cut-off edit shows a grant: %+v", changes[0])
	}
	if !changes[1].Complete || len(changes[1].Rows) != 5 {
		t.Fatalf("the whole edit = %+v", changes[1])
	}
	rendered := get(t, browserClient, harness.site.URL+"/events")
	if !strings.Contains(rendered.body, "Part of this edit is no longer in the event history") {
		t.Fatalf("the Events screen does not say the edit is cut off: %s", rendered.body)
	}
}
