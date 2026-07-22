//go:build linux

// ---
// relationships:
//   verifies: terminal-interface
// ---

package tui

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wyrd-company/wyrwood/internal/control"
)

func key(value string) tea.KeyMsg {
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(value)}
}

func runCommand(t *testing.T, model *Model, command tea.Cmd) {
	t.Helper()
	if command == nil {
		t.Fatal("expected command")
	}
	model.Update(command())
}

func TestSettingsEditsCompleteTimeoutSetWithValidationAndConflictPreservation(t *testing.T) {
	client := populatedClient()
	model := readyModelWithClient(t, client)
	model.Update(key("s"))
	if model.route != routeSettings || model.editor == nil || model.editor.kind != editTimeouts {
		t.Fatalf("settings did not open: route %d editor %#v", model.route, model.editor)
	}
	model.editor.inputs[0].SetValue("99ms")
	model.editor.syncDirty()
	if model.editor.validate(model) || !strings.Contains(model.View(), "INVALID") {
		t.Fatalf("invalid timeout enabled save:\n%s", model.View())
	}
	model.editor.inputs[0].SetValue("100ms")
	model.editor.syncDirty()
	client.changeErr = &control.RemoteError{Code: control.ErrorConfigurationConflict}
	model.editor.focus = model.editor.saveFocus()
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	runCommand(t, model, command)
	if !model.editor.conflict || !model.editor.dirty || model.editor.inputs[0].Value() != "100ms" {
		t.Fatalf("conflict did not preserve candidate: %#v", model.editor)
	}
	if !strings.Contains(model.View(), "CONFLICT") || !strings.Contains(model.View(), "Reload") {
		t.Fatalf("conflict actions absent:\n%s", model.View())
	}
}

func TestSettingsFocusOrderAndEveryTimeoutBoundary(t *testing.T) {
	model := readyModel(t, false)
	model.Update(key("s"))
	model.editor.inputs[0].SetValue("6s")
	model.editor.syncDirty()
	model.editor.validate(model)
	wantFocus := []int{1, 2, 3, model.editor.saveFocus(), model.editor.cancelFocus(), 0}
	for _, want := range wantFocus {
		model.Update(tea.KeyMsg{Type: tea.KeyTab})
		if model.editor.focus != want {
			t.Fatalf("settings focus = %d, want %d", model.editor.focus, want)
		}
	}

	tests := []struct {
		field int
		value string
		valid bool
	}{
		{0, "99ms", false}, {0, "100ms", true}, {0, "30s", true}, {0, "30s1ns", false},
		{1, "99ms", false}, {1, "100ms", true}, {1, "30s", true}, {1, "30s1ns", false},
		{2, "99ms", false}, {2, "100ms", true}, {2, "30s", true}, {2, "30s1ns", false},
		{3, "999ms", false}, {3, "1s", true}, {3, "10m", true}, {3, "10m1ns", false},
	}
	for _, test := range tests {
		model := readyModel(t, false)
		model.Update(key("s"))
		model.editor.inputs[test.field].SetValue(test.value)
		model.editor.syncDirty()
		if got := model.editor.validate(model); got != test.valid {
			t.Errorf("field %d value %q valid = %v, want %v (%#v)", test.field, test.value, got, test.valid, model.editor.errors)
		}
	}
}

func TestConsumerEditorUnionsConfiguredAndOfferedFingerprintsSafely(t *testing.T) {
	client := populatedClient()
	model := readyModelWithClient(t, client)
	configuredOnly := "SHA256:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA"
	model.consumers[0].Fingerprints = []string{sampleFingerprint, configuredOnly}
	model.setConsumerItems()
	model.focus = focusConsumers
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model.Update(key("e"))
	if model.editor == nil || model.editor.kind != editConsumer {
		t.Fatal("consumer editor did not open")
	}
	if got, want := model.editor.fingerprints, []fingerprintChoice{
		{Fingerprint: sampleFingerprint, Display: "sample primary", Selected: true, Offered: true},
		{Fingerprint: "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA", Display: "sample alternate", Offered: true},
		{Fingerprint: configuredOnly, Selected: true},
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("fingerprint union = %#v, want %#v", got, want)
	}
	model.editor.focus = model.editor.fingerprintFocus()
	model.editor.fingerprintIndex = 2
	model.Update(tea.KeyMsg{Type: tea.KeySpace})
	if model.editor.fingerprints[2].Selected || !strings.Contains(model.View(), "UNAVAILABLE") {
		t.Fatalf("configured-only choice not explicit/editable:\n%s", model.View())
	}
	model.editor.focus = model.editor.saveFocus()
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	runCommand(t, model, command)
	if len(client.mutations) != 1 || contains(client.mutations[0].consumer.Fingerprints, configuredOnly) {
		t.Fatalf("explicit fingerprint removal not sent exactly: %#v", client.mutations)
	}
}

func TestUnavailableUpstreamPreservesConfiguredFingerprintChoices(t *testing.T) {
	model := readyModel(t, false)
	consumer, _ := model.selectedConsumer()
	model.keys = Keys{}
	model.keysState = loadUnavailable
	model.openConsumerEditor(&consumer)
	if len(model.editor.fingerprints) != len(consumer.Fingerprints) || !model.editor.fingerprints[0].Selected || model.editor.fingerprints[0].Offered {
		t.Fatalf("unavailable keys lost configured policy: %#v", model.editor.fingerprints)
	}
}

func TestFingerprintAdditionIsAnExactExplicitMutation(t *testing.T) {
	client := populatedClient()
	model := readyModelWithClient(t, client)
	consumer, _ := model.selectedConsumer()
	model.openConsumerEditor(&consumer)
	model.editor.setFocus(model.editor.fingerprintFocus())
	model.editor.fingerprintIndex = 1
	model.Update(tea.KeyMsg{Type: tea.KeySpace})
	model.editor.setFocus(model.editor.saveFocus())
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	runCommand(t, model, command)
	want := []string{sampleFingerprint, "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"}
	if len(client.mutations) != 1 || !reflect.DeepEqual(client.mutations[0].consumer.Fingerprints, want) {
		t.Fatalf("fingerprint addition mutation = %#v, want %#v", client.mutations, want)
	}
}

func TestExplicitKeyRefreshRebuildsUnionWithoutLosingSelection(t *testing.T) {
	model := readyModel(t, false)
	consumer, _ := model.selectedConsumer()
	model.openConsumerEditor(&consumer)
	model.editor.fingerprints[0].Selected = false
	model.editor.syncDirty()
	newFingerprint := "SHA256:DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDQ"
	model.Update(keysMsg{generation: model.generation, result: Keys{Keys: []Key{
		{Fingerprint: sampleFingerprint, Display: "updated label"},
		{Fingerprint: newFingerprint, Display: "new offer"},
	}}})
	if len(model.editor.fingerprints) != 2 || model.editor.fingerprints[0].Selected || model.editor.fingerprints[1].Fingerprint != newFingerprint || model.editor.fingerprints[1].Selected {
		t.Fatalf("refreshed union changed authority: %#v", model.editor.fingerprints)
	}
}

func TestNewConsumerValidationSaveAndSocketChangePrincipalWarning(t *testing.T) {
	client := populatedClient()
	model := readyModelWithClient(t, client)
	model.Update(key("n"))
	if model.editor == nil || model.editor.kind != editConsumer || model.editor.consumerID != nil {
		t.Fatal("new consumer form did not open")
	}
	model.editor.inputs[0].SetValue("sample gamma")
	model.editor.inputs[1].SetValue("relative.sock")
	model.editor.syncDirty()
	if model.editor.validate(model) || !strings.Contains(model.View(), "absolute path") {
		t.Fatalf("relative socket accepted:\n%s", model.View())
	}
	model.editor.inputs[1].SetValue("/tmp/example/gamma/agent.sock")
	model.editor.inputs[2].SetValue("17")
	model.editor.syncDirty()
	model.editor.focus = model.editor.saveFocus()
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	runCommand(t, model, command)
	if len(client.mutations) != 1 || client.mutations[0].operation != "put-consumer" || client.mutations[0].consumer.AccessGroup == nil || *client.mutations[0].consumer.AccessGroup != 17 {
		t.Fatalf("put mutation = %#v", client.mutations)
	}

	model = readyModel(t, false)
	model.focus = focusConsumers
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model.Update(key("e"))
	model.editor.inputs[1].SetValue("/tmp/example/replacement/agent.sock")
	model.editor.syncDirty()
	if !strings.Contains(model.View(), "NEW SECURITY PRINCIPAL") {
		t.Fatalf("socket replacement warning absent:\n%s", model.View())
	}
}

func TestDirtyCancelAndExitRequireExplicitDiscard(t *testing.T) {
	model := readyModel(t, false)
	model.Update(key("s"))
	model.editor.inputs[0].SetValue("6s")
	model.editor.syncDirty()
	model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if model.modal != modalDiscard || model.editor == nil {
		t.Fatal("dirty escape did not request discard")
	}
	model.Update(key("k"))
	if model.modal != modalNone || model.editor == nil {
		t.Fatal("keep editing did not return to candidate")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	if model.modal != modalExit || model.closed {
		t.Fatal("dirty quit did not request discard")
	}
	model.Update(key("d"))
	if !model.closed {
		t.Fatal("explicit discard did not exit")
	}
}

func TestKeepEditingResetsExternalInterruptConfirmation(t *testing.T) {
	for _, initial := range []modalKind{modalExit, modalDiscard} {
		for _, dismiss := range []tea.KeyMsg{key("k"), {Type: tea.KeyEsc}} {
			t.Run(fmt.Sprintf("modal-%d-%s", initial, dismiss.String()), func(t *testing.T) {
				resets := 0
				model := readyModel(t, false)
				model.resetInterrupt = func() { resets++ }
				model.Update(key("s"))
				model.editor.inputs[0].SetValue("6s")
				model.editor.syncDirty()
				if initial == modalExit {
					model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
				} else {
					model.Update(tea.KeyMsg{Type: tea.KeyEsc})
					model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
				}
				if model.modal != initial {
					t.Fatalf("initial modal = %d, want %d", model.modal, initial)
				}
				model.Update(dismiss)
				if resets != 1 || model.modal != modalNone {
					t.Fatalf("interrupt reset = %d, modal = %d", resets, model.modal)
				}
				model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
				if model.modal != modalExit || model.closed {
					t.Fatal("later interrupt did not open a fresh confirmation")
				}
			})
		}
	}
}

func TestRetireRequiresNamedConfirmationAndUsesBaseRevision(t *testing.T) {
	client := populatedClient()
	model := readyModelWithClient(t, client)
	model.focus = focusConsumers
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model.Update(key("x"))
	if model.modal != modalRetire || !strings.Contains(model.View(), "sample alpha") || !strings.Contains(model.View(), "removes only the owned socket") {
		t.Fatalf("retirement confirmation incomplete:\n%s", model.View())
	}
	_, command := model.Update(key("y"))
	runCommand(t, model, command)
	if len(client.mutations) != 1 || client.mutations[0].operation != "retire-consumer" || client.mutations[0].revision != strings.Repeat("1", 64) {
		t.Fatalf("retirement mutation = %#v", client.mutations)
	}
}

func TestUncertainRetirementProactivelyRefetchesWithoutClaimingOutcome(t *testing.T) {
	client := populatedClient()
	client.changeErr = &control.RemoteError{Code: control.ErrorConfigurationDurabilityUncertain}
	model := readyModelWithClient(t, client)
	model.focus = focusConsumers
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model.Update(key("x"))
	_, retire := model.Update(key("y"))
	before := model.generation
	_, refresh := model.Update(retire())
	if refresh == nil || model.generation != before+1 || !model.noticeSticky || !strings.Contains(model.notice, "COMMIT UNCERTAIN") || strings.Contains(model.notice, "COMMITTED") {
		t.Fatalf("uncertain retirement = generation %d/%d notice %q refresh %v", before, model.generation, model.notice, refresh)
	}
}

func TestApplyOutcomesAreCategoricalAndCommittedDegradedRefreshes(t *testing.T) {
	client := populatedClient()
	client.applyResult = ApplyResult{Revision: strings.Repeat("2", 64), Committed: true, Degraded: true, PendingCleanup: 2, PendingPermissions: 1}
	model := readyModelWithClient(t, client)
	_, command := model.Update(key("a"))
	runCommand(t, model, command)
	if !strings.Contains(model.View(), "COMMITTED DEGRADED") || !strings.Contains(model.View(), "cleanup 2") || model.generation < 2 {
		t.Fatalf("degraded apply not represented/refreshed:\n%s", model.View())
	}

	client = populatedClient()
	client.applyErr = &control.RemoteError{Code: control.ErrorApplyFailed}
	model = readyModelWithClient(t, client)
	_, command = model.Update(key("a"))
	runCommand(t, model, command)
	if !strings.Contains(model.View(), "APPLY REJECTED") || strings.Contains(model.View(), "rollback") {
		t.Fatalf("rejected apply representation invalid:\n%s", model.View())
	}
}

func TestConfigurationRefreshMarksDirtyEditorConflictedWithoutReplacingCandidate(t *testing.T) {
	model := readyModel(t, false)
	model.Update(key("s"))
	model.editor.inputs[0].SetValue("6s")
	model.editor.syncDirty()
	candidate := model.editor.inputs[0].Value()
	model.startRefresh(true, false)
	generation := model.generation
	page := model.configuration
	page.Revision = strings.Repeat("9", 64)
	model.Update(configurationMsg{generation: generation, page: page})
	if !model.editor.conflict || model.editor.inputs[0].Value() != candidate {
		t.Fatalf("external revision replaced dirty candidate: %#v", model.editor)
	}
}

func TestFailedConfigurationRefreshPreservesCompleteDirtyValidationBase(t *testing.T) {
	model := readyModel(t, false)
	model.Update(key("s"))
	model.editor.inputs[0].SetValue("6s")
	model.editor.syncDirty()
	beforeConsumers := append([]Consumer(nil), model.consumers...)
	model.startRefresh(true, false)
	model.Update(configurationMsg{generation: model.generation, err: errors.New("transport detail")})
	if !reflect.DeepEqual(model.consumers, beforeConsumers) || model.configurationState != loadReady || !model.editor.validate(model) || !strings.Contains(model.editor.failure, "candidate preserved") {
		t.Fatalf("failed refresh damaged dirty base: state %s, consumers %#v, editor %#v", model.configurationState, model.consumers, model.editor)
	}
}

func TestConflictReloadDiscardsCandidateAndLoadsOneCoherentRevision(t *testing.T) {
	client := populatedClient()
	model := readyModelWithClient(t, client)
	model.Update(key("s"))
	model.editor.inputs[0].SetValue("6s")
	model.editor.syncDirty()
	model.editor.conflict = true
	for offset, page := range client.configurationPages {
		page.Revision = strings.Repeat("9", 64)
		page.Timeouts.Connect = "7s"
		client.configurationPages[offset] = page
	}
	_, command := model.Update(key("R"))
	runAllCommands(model, command)
	if model.editor == nil || model.editor.dirty || model.editor.conflict || model.editor.baseRevision != strings.Repeat("9", 64) || model.editor.inputs[0].Value() != "7s" {
		t.Fatalf("reload did not replace candidate coherently: %#v", model.editor)
	}
}

func TestConflictReloadFailurePreservesCandidateAndCompleteBase(t *testing.T) {
	model := readyModel(t, false)
	model.Update(key("s"))
	model.editor.inputs[0].SetValue("6s")
	model.editor.syncDirty()
	model.editor.conflict = true
	beforeConsumers := append([]Consumer(nil), model.consumers...)
	_, command := model.Update(key("R"))
	if command == nil || !model.editor.reloading {
		t.Fatal("reload did not start")
	}
	model.Update(configurationMsg{generation: model.generation, err: errors.New("private transport detail")})
	if model.editor.reloading || model.editor.inputs[0].Value() != "6s" || !reflect.DeepEqual(model.consumers, beforeConsumers) || strings.Contains(model.View(), "private transport detail") {
		t.Fatalf("failed reload damaged candidate/base: %#v\n%s", model.editor, model.View())
	}
}

func TestUpstreamBrowserIsInjectedAndSelectionIsOnlyAdvisory(t *testing.T) {
	browser := &fakeBrowser{entries: []SocketEntry{{Path: "/tmp/example/offered.sock", Socket: true}}}
	model := readyModel(t, false)
	model.browser = browser
	model.focus = focusUpstream
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	model.Update(key("e"))
	model.editor.setFocus(model.editor.browseFocus())
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	runCommand(t, model, command)
	if len(browser.parents) != 1 || browser.parents[0] != "/tmp/example" || !model.browserState.active {
		t.Fatalf("browser request/state = %#v / %#v", browser.parents, model.browserState)
	}
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if model.editor.inputs[0].Value() != "/tmp/example/offered.sock" || !strings.Contains(model.View(), "ADVISORY ONLY") {
		t.Fatalf("browser selection not copied as advisory value:\n%s", model.View())
	}
}

func TestBrowserQuitRoutesThroughDirtyExitConfirmation(t *testing.T) {
	for _, quit := range []tea.KeyMsg{key("q"), {Type: tea.KeyCtrlC}} {
		model := readyModel(t, false)
		model.focus = focusUpstream
		model.Update(tea.KeyMsg{Type: tea.KeyEnter})
		model.Update(key("e"))
		model.editor.inputs[0].SetValue("/tmp/example/changed.sock")
		model.editor.syncDirty()
		model.browserState = browserViewState{active: true, state: loadReady}
		model.Update(quit)
		if model.browserState.active || model.modal != modalExit || model.closed {
			t.Fatalf("browser quit %q = browser %#v modal %d closed %v", quit.String(), model.browserState, model.modal, model.closed)
		}
	}
}

func TestLinuxSocketBrowserOffersOnlyDirectoriesAndSockets(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "regular"), []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", filepath.Join(root, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	listing, err := (linuxSocketBrowser{}).Browse(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	entries := listing.Entries
	if len(entries) != 2 || entries[0].Path != filepath.Join(root, "agent.sock") || !entries[0].Socket || entries[1].Path != filepath.Join(root, "nested") || !entries[1].Directory || listing.Truncated {
		t.Fatalf("browser entries = %#v", listing)
	}
}

func TestLinuxSocketBrowserBoundsHostileDirectoriesAndReportsIncomplete(t *testing.T) {
	root := t.TempDir()
	for index := 0; index <= maximumBrowserScanEntries; index++ {
		name := filepath.Join(root, fmt.Sprintf("entry-%04d", index))
		if err := os.WriteFile(name, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	listing, err := (linuxSocketBrowser{}).Browse(context.Background(), root)
	if err != nil || !listing.Truncated || len(listing.Entries) != 0 {
		t.Fatalf("bounded listing = (%#v, %v)", listing, err)
	}
	model := readyModel(t, false)
	model.browserState = browserViewState{active: true, state: loadEmpty, truncated: true, parent: root}
	if view := model.View(); !strings.Contains(view, "BROWSE INCOMPLETE") || !strings.Contains(view, "manual entry") {
		t.Fatalf("truncation not represented:\n%s", view)
	}
}

type fakeBrowser struct {
	entries []SocketEntry
	err     error
	parents []string
}

func (browser *fakeBrowser) Browse(_ context.Context, parent string) (SocketListing, error) {
	browser.parents = append(browser.parents, parent)
	return SocketListing{Entries: browser.entries}, browser.err
}

func readyModelWithClient(t *testing.T, client *fakeClient) *Model {
	t.Helper()
	model := NewModel(client, options{Schedule: noSchedule})
	model.Init()
	generation := model.generation
	_, command := model.Update(configurationMsg{generation: generation, offset: 0, page: client.configurationPages[0]})
	model.Update(command())
	model.Update(keysMsg{generation: generation, result: client.keys})
	model.Update(statusMsg{generation: generation, result: client.status})
	model.Update(eventsMsg{generation: generation, result: client.events})
	return model
}

func runAllCommands(model *Model, commands ...tea.Cmd) {
	for len(commands) > 0 {
		command := commands[0]
		commands = commands[1:]
		if command == nil {
			continue
		}
		message := command()
		if batch, ok := message.(tea.BatchMsg); ok {
			commands = append(commands, batch...)
			continue
		}
		_, next := model.Update(message)
		commands = append(commands, next)
	}
}

func contains(values []string, value string) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}

func TestMutationFailureNeverRendersRawError(t *testing.T) {
	client := populatedClient()
	client.changeErr = errors.New("/private/path: internal detail")
	model := readyModelWithClient(t, client)
	model.Update(key("s"))
	model.editor.inputs[0].SetValue("6s")
	model.editor.syncDirty()
	model.editor.focus = model.editor.saveFocus()
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	runCommand(t, model, command)
	view := model.View()
	if strings.Contains(view, "/private/path") || !strings.Contains(view, "DISCONNECTED") {
		t.Fatalf("raw mutation error leaked:\n%s", view)
	}
}

func TestDurabilityUncertaintyNeverClaimsSaveWasRejectedOrRolledBack(t *testing.T) {
	client := populatedClient()
	client.changeErr = &control.RemoteError{Code: control.ErrorConfigurationDurabilityUncertain}
	model := readyModelWithClient(t, client)
	model.Update(key("s"))
	model.editor.inputs[0].SetValue("6s")
	model.editor.syncDirty()
	model.editor.validate(model)
	model.editor.focus = model.editor.saveFocus()
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	_, verification := model.Update(command())
	view := model.View()
	if verification == nil || !model.editor.verifying || !strings.Contains(view, "COMMIT UNCERTAIN") || strings.Contains(view, "REJECTED") || strings.Contains(strings.ToLower(view), "rollback") || !model.editor.dirty {
		t.Fatalf("durability uncertainty misrepresented:\n%s", view)
	}
}

func TestDurabilityUncertaintyRefetchClassifiesOnlyExactBaseOrCandidate(t *testing.T) {
	tests := []struct {
		name      string
		revision  func(*Model) string
		connect   string
		published bool
		conflict  bool
	}{
		{name: "not-published", revision: func(model *Model) string { return model.editor.baseRevision }, connect: "1s"},
		{name: "published", revision: func(model *Model) string { revision, _ := model.editor.candidateRevision(model); return revision }, connect: "6s", published: true},
		{name: "external-same-target", revision: func(*Model) string { return strings.Repeat("9", 64) }, connect: "6s", conflict: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := populatedClient()
			client.changeErr = &control.RemoteError{Code: control.ErrorConfigurationDurabilityUncertain}
			model := readyModelWithClient(t, client)
			model.Update(key("s"))
			model.editor.inputs[0].SetValue("6s")
			model.editor.syncDirty()
			model.editor.validate(model)
			revision := test.revision(model)
			model.editor.focus = model.editor.saveFocus()
			_, save := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
			_, verification := model.Update(save())
			if verification == nil || !model.editor.verifying || !model.noticeSticky {
				t.Fatalf("verification did not start: editor %#v notice %q", model.editor, model.notice)
			}
			page0 := client.configurationPages[0]
			page1 := client.configurationPages[1]
			page0.Revision, page1.Revision = revision, revision
			page0.Timeouts.Connect = test.connect
			generation := model.generation
			_, next := model.Update(configurationMsg{generation: generation, offset: 0, page: page0})
			if next == nil {
				t.Fatal("verification did not request coherent next page")
			}
			model.Update(configurationMsg{generation: generation, offset: 1, page: page1})
			if test.published {
				if model.editor != nil || model.configuration.Revision != revision || !strings.Contains(model.notice, "VERIFIED PUBLISHED") || model.noticeSticky {
					t.Fatalf("published verification = editor %#v revision %q notice %q sticky %v", model.editor, model.configuration.Revision, model.notice, model.noticeSticky)
				}
				return
			}
			if model.editor == nil || !model.editor.dirty || model.editor.inputs[0].Value() != "6s" {
				t.Fatalf("verification lost candidate: %#v", model.editor)
			}
			if test.conflict {
				if !model.editor.conflict || !model.noticeSticky || !strings.Contains(model.notice, "CONFLICT") {
					t.Fatalf("external change did not conflict: %#v notice %q", model.editor, model.notice)
				}
			} else if model.editor.conflict || model.editor.verifying || model.noticeSticky || !strings.Contains(model.notice, "NOT COMMITTED") {
				t.Fatalf("base verification misclassified: %#v notice %q", model.editor, model.notice)
			}
		})
	}
}

func TestCleanEditorAlwaysBuffersACompleteConfigurationReload(t *testing.T) {
	client := populatedClient()
	model := readyModelWithClient(t, client)
	model.Update(key("s"))
	if model.editor.dirty || model.editor.reloading {
		t.Fatalf("unexpected initial editor state: %#v", model.editor)
	}
	generation := model.generation
	_, next := model.Update(configurationMsg{generation: generation, offset: 0, page: client.configurationPages[0]})
	if next == nil || !model.editor.reloading || len(model.editor.reloadConsumers) != 1 {
		t.Fatalf("page zero was not buffered: %#v", model.editor)
	}
	model.Update(configurationMsg{generation: generation, offset: 1, page: client.configurationPages[1]})
	if model.editor == nil || model.editor.reloading || model.configuration.Upstream == "" || len(model.consumers) != 2 || model.editor.inputs[0].Value() != "1s" {
		t.Fatalf("coherent reload committed incomplete state: config %#v consumers %d editor %#v", model.configuration, len(model.consumers), model.editor)
	}
}

func TestTransientNoticeClearsOnNextNavigationWithoutHidingRevisionState(t *testing.T) {
	client := populatedClient()
	client.applyResult = ApplyResult{Revision: strings.Repeat("2", 64), Committed: true}
	model := readyModelWithClient(t, client)
	_, apply := model.Update(key("a"))
	model.Update(apply())
	if !strings.Contains(model.notice, "APPLIED") {
		t.Fatalf("apply notice = %q", model.notice)
	}
	model.Update(tea.KeyMsg{Type: tea.KeyTab})
	if model.notice != "" || model.configuration.Revision == "" || model.status.ActiveRevision == model.configuration.Revision {
		t.Fatalf("navigation notice/revision = %q\n%s", model.notice, model.View())
	}
}

func TestMutationInFlightBlocksDuplicateActionsAndCandidateChanges(t *testing.T) {
	client := populatedClient()
	model := readyModelWithClient(t, client)
	model.Update(key("s"))
	model.editor.inputs[0].SetValue("6s")
	model.editor.syncDirty()
	model.editor.validate(model)
	model.editor.focus = model.editor.saveFocus()
	_, command := model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if command == nil || !model.editor.saving || !model.mutationInFlight {
		t.Fatal("save did not enter in-flight state")
	}
	before := model.editor.inputs[0].Value()
	model.Update(key("x"))
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if model.editor.inputs[0].Value() != before || model.request != 1 {
		t.Fatalf("in-flight mutation accepted input/action: value %q request %d", model.editor.inputs[0].Value(), model.request)
	}
	runCommand(t, model, command)
	if model.mutationInFlight {
		t.Fatal("settled mutation retained in-flight state")
	}
}
