// ---
// relationships:
//   verifies: web-interface
// ---

package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

const policyRenamePath = "/policies/rename?name="

type renameResponse struct {
	status   int
	location string
	page     string
	data     policyRenamePage
	raw      []byte
}

func readRename(t *testing.T, response *http.Response, err error) renameResponse {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	result := renameResponse{status: response.StatusCode, location: response.Header.Get("Location"), raw: body}
	if match := pageDataPattern.FindSubmatch(body); match != nil {
		var payload struct {
			Page string
			Data policyRenamePage
		}
		if err := json.Unmarshal(match[1], &payload); err != nil {
			t.Fatal(err)
		}
		result.page, result.data = payload.Page, payload.Data
	}
	return result
}

func (fixture listFixture) renameScreen(t *testing.T, name string) renameResponse {
	t.Helper()
	response, err := noRedirects(fixture.client).Get(fixture.harness.site.URL + policyRenamePath + url.QueryEscape(name))
	return readRename(t, response, err)
}

func (fixture listFixture) rename(t *testing.T, name, newName string, revision, generation int) renameResponse {
	t.Helper()
	response, err := noRedirects(fixture.client).PostForm(fixture.harness.site.URL+policyRenamePath+url.QueryEscape(name), url.Values{
		"csrf": {fixture.deleteToken(t)}, "new-name": {newName}, "revision": {strconv.Itoa(revision)}, "generation": {strconv.Itoa(generation)},
	})
	return readRename(t, response, err)
}

func (fixture listFixture) renameSaved(t *testing.T, saved policy.Policy, newName string) renameResponse {
	t.Helper()
	return fixture.rename(t, saved.Name, newName, saved.Revision, saved.Generation)
}

func (fixture listFixture) lastRenameEvent(t *testing.T) events.Event {
	t.Helper()
	var last *events.Event
	recent := fixture.harness.controller.Events().Recent(1000)
	for index := range recent {
		if recent[index].Operation == events.OperationPolicyRenamed {
			last = &recent[index]
		}
	}
	if last == nil {
		t.Fatal("no policy-renamed event")
	}
	return *last
}

// bound publishes a policy and binds two containers to it through the controller,
// so that OpenBao holds its role and a rename has a real transition.
func (fixture listFixture) bound(t *testing.T, name string) (policy.Policy, []store.Binding) {
	t.Helper()
	saved := fixture.published(t, name)
	var bindings []store.Binding
	for _, container := range []string{"first-container", "second-container"} {
		binding, err := fixture.harness.controller.CreateBinding(fixture.ctx, "empty", protocol.Key{Kind: protocol.KeyName, Value: container}, policy.Selection{Policies: []string{name}}, "operator")
		if err != nil {
			t.Fatal(err)
		}
		bindings = append(bindings, binding)
	}
	return saved, bindings
}

func TestPolicyRenameScreenStatesTheConsequence(t *testing.T) {
	fixture := newListFixture(t)
	fixture.published(t, freePolicy)
	free := fixture.renameScreen(t, freePolicy)
	if free.status != http.StatusOK || free.page != "policy-rename" || free.data.Name != freePolicy || free.data.NewName != freePolicy ||
		free.data.Identity != freePolicyACL || !strings.Contains(free.data.Consequence, "No binding") || len(free.data.Bindings) != 0 ||
		free.data.Action != policyRenamePath+freePolicy || free.data.Back != policyPath(freePolicy) {
		t.Fatalf("free = %d %#v", free.status, free.data)
	}
	saved, _ := fixture.bound(t, "scratch-bound")
	screen := fixture.renameScreen(t, saved.Name)
	if !strings.Contains(screen.data.Consequence, "2 bindings select this policy") || !strings.Contains(screen.data.Consequence, "fresh credential") ||
		!strings.Contains(screen.data.Consequence, "token lifetime is unchanged") || len(screen.data.Bindings) != 2 {
		t.Fatalf("bound = %#v", screen.data)
	}
	if screen.data.Revision != saved.Revision || screen.data.Generation != saved.Generation {
		t.Fatalf("binding fields = %#v", screen.data)
	}
}

// Every surface shows the new name after a rename of a bound policy.
func TestPolicyRenamePostMovesAPolicyAndItsBindings(t *testing.T) {
	fixture := newListFixture(t)
	saved, bindings := fixture.bound(t, "scratch-bound")
	before, err := fixture.harness.controller.Store().Binding(fixture.ctx, "b-a-sample")
	if err != nil {
		t.Fatal(err)
	}
	done := fixture.renameSaved(t, saved, "scratch-moved")
	if done.status != http.StatusSeeOther || done.location != policyPath("scratch-moved")+"&notice=policy-renamed" {
		t.Fatalf("rename = %d %q %s", done.status, done.location, done.raw)
	}
	if fixture.stored(t, saved.Name) || !fixture.stored(t, "scratch-moved") {
		t.Fatal("rows did not move")
	}
	if fixture.acl(t, "wyrwood-scratch-bound") != "" || fixture.acl(t, "wyrwood-scratch-moved") == "" {
		t.Fatal("identities did not move")
	}
	data := fixture.harness.controller.Store()
	for _, binding := range bindings {
		after, err := data.Binding(fixture.ctx, binding.ID)
		if err != nil || after.Policies[0] != "scratch-moved" || !after.Applied || after.Revision != binding.Revision+1 {
			t.Fatalf("binding = %#v, %v", after, err)
		}
	}
	untouched, err := data.Binding(fixture.ctx, "b-a-sample")
	if err != nil || untouched.Assignment() != before.Assignment() {
		t.Fatalf("an unrelated binding changed: %v", err)
	}
	editor := loadPage[policyPage](t, fixture, done.location, "policy")
	if editor.Name != "scratch-moved" || editor.Bindings != 2 || len(editor.BindingRows) != 2 || editor.PolicyPath != "sys/policies/acl/wyrwood-scratch-moved" {
		t.Fatalf("editor = %#v", editor)
	}
	if !strings.Contains(editor.Notice, "renamed") {
		t.Fatalf("editor notice = %q", editor.Notice)
	}
	list := get(t, fixture.client, fixture.harness.site.URL+"/policies")
	if !strings.Contains(list.body, "scratch-moved") || strings.Contains(list.body, "scratch-bound") {
		t.Fatal("the policy list shows the wrong name")
	}
	rows := fixture.bindings(t, "")
	found := 0
	for _, row := range rows.Rows {
		for _, name := range row.Policies {
			if name == saved.Name {
				t.Fatalf("binding row keeps the old name: %#v", row)
			}
			if name == "scratch-moved" {
				found++
			}
		}
	}
	if found != 2 {
		t.Fatalf("binding rows with the new name = %d", found)
	}
	event := fixture.lastRenameEvent(t)
	if event.Policy != saved.Name || event.NewPolicy != "scratch-moved" || event.Outcome != events.OutcomeOK || event.Operator == "" {
		t.Fatalf("event = %#v", event)
	}
	// Earlier events keep the old name.
	sawOld := false
	for _, recorded := range fixture.harness.controller.Events().Recent(1000) {
		if recorded.Operation == events.OperationPolicySaved && recorded.Policy == saved.Name {
			sawOld = true
		}
	}
	if !sawOld {
		t.Fatal("an earlier event lost the old name")
	}
	history := get(t, fixture.client, fixture.harness.site.URL+"/events")
	if !strings.Contains(history.body, "scratch-bound · scratch-moved") {
		t.Fatal("the event page does not show both names")
	}
}

func TestPolicyRenameToTheSameNameRedirectsAndChangesNothing(t *testing.T) {
	fixture := newListFixture(t)
	saved := fixture.published(t, freePolicy)
	done := fixture.renameSaved(t, saved, freePolicy)
	if done.status != http.StatusSeeOther || done.location != policyPath(freePolicy) {
		t.Fatalf("rename = %d %q", done.status, done.location)
	}
	stored, err := fixture.harness.controller.Store().Policy(fixture.ctx, freePolicy)
	if err != nil || stored.Policy.Revision != saved.Revision {
		t.Fatalf("stored = %#v, %v", stored, err)
	}
	for _, event := range fixture.harness.controller.Events().Recent(1000) {
		if event.Operation == events.OperationPolicyRenamed {
			t.Fatalf("recorded %#v", event)
		}
	}
}

func TestPolicyRenameRefusalsKeepTheFormAndTheReason(t *testing.T) {
	fixture := newListFixture(t)
	saved := fixture.published(t, freePolicy)
	fixture.published(t, "taken-name")
	for label, row := range map[string]struct {
		newName    string
		revision   int
		generation int
		want       string
	}{
		"invalid":          {"Not Valid", saved.Revision, saved.Generation, "lower-kebab-case"},
		"in use":           {"taken-name", saved.Revision, saved.Generation, "already in use"},
		"stale revision":   {"scratch-moved", saved.Revision + 1, saved.Generation, "reload"},
		"stale generation": {"scratch-moved", saved.Revision, saved.Generation + 1, "reload"},
		"no fields":        {"scratch-moved", 0, 0, "reload"},
	} {
		t.Run(label, func(t *testing.T) {
			refused := fixture.rename(t, freePolicy, row.newName, row.revision, row.generation)
			if refused.status != http.StatusUnprocessableEntity || refused.page != "policy-rename" || !strings.Contains(refused.data.Problem, row.want) || refused.data.NewName != row.newName {
				t.Fatalf("refused = %d %#v", refused.status, refused.data)
			}
			if refused.data.Revision != saved.Revision || refused.data.Generation != saved.Generation || refused.data.Identity != freePolicyACL {
				t.Fatalf("form = %#v", refused.data)
			}
			if !fixture.stored(t, freePolicy) || fixture.acl(t, freePolicyACL) == "" || fixture.acl(t, "wyrwood-scratch-moved") != "" {
				t.Fatal("a refused rename changed state")
			}
		})
	}
}

func TestPolicyRenameReplayIsAClearMessage(t *testing.T) {
	fixture := newListFixture(t)
	saved := fixture.published(t, freePolicy)
	if done := fixture.renameSaved(t, saved, "scratch-moved"); done.status != http.StatusSeeOther {
		t.Fatalf("rename = %d %s", done.status, done.raw)
	}
	replay := fixture.renameSaved(t, saved, "scratch-moved")
	if replay.status != http.StatusNotFound || !strings.Contains(string(replay.raw), "renamed it") {
		t.Fatalf("replay = %d %s", replay.status, replay.raw)
	}
	moved, err := fixture.harness.controller.Store().Policy(fixture.ctx, "scratch-moved")
	if err != nil || moved.Policy.Revision != saved.Revision+1 {
		t.Fatalf("moved = %#v, %v", moved, err)
	}
	gone := fixture.renameScreen(t, freePolicy)
	if gone.status != http.StatusNotFound {
		t.Fatalf("screen of a renamed policy = %d", gone.status)
	}
}

// A real denial after the commit: the controller's policy loses delete on managed
// policies. The operator lands on the new name with a pending notice, and the old
// ACL stays while the denial holds.
func TestPolicyRenameThatIsPendingLandsOnTheNewName(t *testing.T) {
	fixture := newListFixture(t)
	saved := fixture.published(t, freePolicy)
	root := fixture.harness.bao.Root.Sys()
	withoutDelete := strings.Replace(baotest.ControllerPolicy,
		`path "sys/policies/acl/wyrwood-*" { capabilities = ["create", "read", "update", "delete", "list"] }`,
		`path "sys/policies/acl/wyrwood-*" { capabilities = ["create", "read", "update", "list"] }`, 1)
	if withoutDelete == baotest.ControllerPolicy {
		t.Fatal("the fault did not change the controller's policy")
	}
	if err := root.PutPolicy(baotest.ControllerName, withoutDelete); err != nil {
		t.Fatal(err)
	}
	done := fixture.renameSaved(t, saved, "scratch-moved")
	if done.status != http.StatusSeeOther || done.location != policyPath("scratch-moved")+"&notice=rename-pending" {
		t.Fatalf("rename = %d %q %s", done.status, done.location, done.raw)
	}
	editor := loadPage[policyPage](t, fixture, policyPath("scratch-moved")+"&notice=rename-pending", "policy")
	if !strings.Contains(editor.Notice, "pending") {
		t.Fatalf("editor notice = %q", editor.Notice)
	}
	if fixture.acl(t, freePolicyACL) == "" {
		t.Fatal("the denial did not hold the old ACL")
	}
	event := fixture.lastRenameEvent(t)
	if event.Outcome != events.OutcomeDenied || event.ErrorCode != events.ErrorOpenBaoDenied {
		t.Fatalf("event = %#v", event)
	}
	if err := root.PutPolicy(baotest.ControllerName, baotest.ControllerPolicy); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyRenameAnswersAnErrorWhenAReadFails(t *testing.T) {
	fixture := newListFixture(t)
	database := openStore(t, fixture.harness)
	saved := fixture.published(t, freePolicy)
	inventoryFault("host-a").during(t, database, func() {
		screen := fixture.renameScreen(t, boundPolicy)
		if screen.status != http.StatusInternalServerError || !strings.Contains(string(screen.raw), bindingsUnreadable) {
			t.Fatalf("screen = %d %s", screen.status, screen.raw)
		}
	})
	policyFault := storeFault{name: "policies", apply: `ALTER TABLE policies RENAME TO policies_unavailable`, restore: `ALTER TABLE policies_unavailable RENAME TO policies`}
	policyFault.during(t, database, func() {
		screen := fixture.renameScreen(t, freePolicy)
		if screen.status != http.StatusInternalServerError || screen.page != "" {
			t.Fatalf("screen = %d %s", screen.status, screen.raw)
		}
		failed := fixture.renameSaved(t, saved, "scratch-moved")
		if failed.status != http.StatusInternalServerError || !strings.Contains(string(failed.raw), "could not be read") {
			t.Fatalf("rename = %d %s", failed.status, failed.raw)
		}
	})
	if !fixture.stored(t, freePolicy) || fixture.acl(t, freePolicyACL) == "" || fixture.acl(t, "wyrwood-scratch-moved") != "" {
		t.Fatal("a failed read changed the policy")
	}
}

func TestPolicyRenameRoutesRequireASession(t *testing.T) {
	fixture := newListFixture(t)
	fixture.published(t, freePolicy)
	anonymous := noRedirects(browser(t))
	target := fixture.harness.site.URL + policyRenamePath + freePolicy
	response, err := anonymous.Get(target)
	screen := readRename(t, response, err)
	if screen.status != http.StatusSeeOther || screen.location != "/sign-in" || screen.page != "" {
		t.Fatalf("anonymous screen = %d %q", screen.status, screen.location)
	}
	response, err = anonymous.PostForm(target, url.Values{"csrf": {fixture.deleteToken(t)}, "new-name": {"scratch-moved"}, "revision": {"1"}, "generation": {"1"}})
	renamed := readRename(t, response, err)
	if renamed.status != http.StatusSeeOther || renamed.location != "/sign-in" {
		t.Fatalf("anonymous rename = %d %q", renamed.status, renamed.location)
	}
	if !fixture.stored(t, freePolicy) || fixture.stored(t, "scratch-moved") {
		t.Fatal("an anonymous request renamed the policy")
	}
}

func TestPolicyRenameRequiresTheAntiForgeryToken(t *testing.T) {
	fixture := newListFixture(t)
	saved := fixture.published(t, freePolicy)
	target := fixture.harness.site.URL + policyRenamePath + freePolicy
	form := url.Values{"new-name": {"scratch-moved"}, "revision": {strconv.Itoa(saved.Revision)}, "generation": {strconv.Itoa(saved.Generation)}}
	for label, token := range map[string][]string{"absent": nil, "wrong": {"not-the-token"}} {
		attempt := url.Values{}
		for key, value := range form {
			attempt[key] = value
		}
		if token != nil {
			attempt["csrf"] = token
		}
		response, err := noRedirects(fixture.client).PostForm(target, attempt)
		refused := readRename(t, response, err)
		if refused.status != http.StatusForbidden {
			t.Fatalf("%s token = %d", label, refused.status)
		}
		if !fixture.stored(t, freePolicy) || fixture.stored(t, "scratch-moved") {
			t.Fatalf("%s token renamed the policy", label)
		}
	}
	if done := fixture.renameSaved(t, saved, "scratch-moved"); done.status != http.StatusSeeOther {
		t.Fatalf("valid token = %d %s", done.status, done.raw)
	}
}

// GET and the HEAD it serves are read-only, and the name comes only from the query.
func TestPolicyRenameScreenIsReadOnly(t *testing.T) {
	fixture := newListFixture(t)
	saved := fixture.published(t, freePolicy)
	target := fixture.harness.site.URL + policyRenamePath + freePolicy
	response, err := noRedirects(fixture.client).Head(target + "&new-name=scratch-moved")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || !fixture.stored(t, freePolicy) || fixture.stored(t, "scratch-moved") {
		t.Fatalf("HEAD = %d", response.StatusCode)
	}
	for _, event := range fixture.harness.controller.Events().Recent(1000) {
		if event.Operation == events.OperationPolicyRenamed {
			t.Fatalf("a read recorded %#v", event)
		}
	}
	response, err = noRedirects(fixture.client).PostForm(fixture.harness.site.URL+"/policies/rename", url.Values{"csrf": {fixture.deleteToken(t)}, "name": {freePolicy}, "new-name": {"scratch-moved"}, "revision": {strconv.Itoa(saved.Revision)}, "generation": {strconv.Itoa(saved.Generation)}})
	missing := readRename(t, response, err)
	if missing.status != http.StatusNotFound || !fixture.stored(t, freePolicy) {
		t.Fatalf("form name = %d", missing.status)
	}
}

func TestPolicyRenameScreenExposesNoCredential(t *testing.T) {
	fixture := newListFixture(t)
	const accessor = "sentinel-accessor-value"
	if err := fixture.harness.controller.Store().SaveTokenAccessor(fixture.ctx, "b-a-sample", accessor, fixture.now); err != nil {
		t.Fatal(err)
	}
	screen := fixture.renameScreen(t, boundPolicy)
	if strings.Contains(string(screen.raw), accessor) {
		t.Fatal("the page exposes a token accessor")
	}
}
