//go:build linux

// ---
// relationships:
//   implements: terminal-interface
//   uses: control-interface
// ---

package tui

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/control"
)

type editKind uint8

const (
	editNone editKind = iota
	editUpstream
	editTimeouts
	editConsumer
	editRetire
)

type modalKind uint8

const (
	modalNone modalKind = iota
	modalDiscard
	modalExit
	modalRetire
)

type fingerprintChoice struct {
	Fingerprint string
	Display     string
	Selected    bool
	Offered     bool
}

type editorState struct {
	kind                 editKind
	baseRevision         string
	returnRoute          route
	consumerID           *string
	originalConsumer     Consumer
	originalValues       []string
	originalSelected     []string
	inputs               []textinput.Model
	focus                int
	fingerprints         []fingerprintChoice
	fingerprintIndex     int
	dirty                bool
	conflict             bool
	saving               bool
	reloading            bool
	verifying            bool
	verificationRevision string
	errors               map[string]string
	failure              string
	reloadConfiguration  ConfigurationPage
	reloadConsumers      []Consumer
}

type mutationMsg struct {
	request uint64
	kind    editKind
	result  ConfigurationChange
	err     error
}

type applyMsg struct {
	request uint64
	result  ApplyResult
	err     error
}

func input(value string, width int) textinput.Model {
	field := textinput.New()
	field.SetValue(value)
	field.Width = width
	field.CharLimit = 512
	field.CursorEnd()
	return field
}

func (model *Model) openUpstreamEditor() {
	editor := &editorState{
		kind: editUpstream, baseRevision: model.configuration.Revision, returnRoute: routeUpstream,
		inputs:         []textinput.Model{input(model.configuration.Upstream, 80)},
		originalValues: []string{model.configuration.Upstream}, errors: map[string]string{},
	}
	model.editor = editor
	editor.setFocus(0)
	editor.validate(model)
}

func (model *Model) openTimeoutEditor() {
	values := []string{model.configuration.Timeouts.Connect, model.configuration.Timeouts.List, model.configuration.Timeouts.Replay, model.configuration.Timeouts.Sign}
	inputs := make([]textinput.Model, len(values))
	for index, value := range values {
		inputs[index] = input(value, 24)
	}
	editor := &editorState{
		kind: editTimeouts, baseRevision: model.configuration.Revision, returnRoute: routeDashboard,
		inputs: inputs, originalValues: append([]string(nil), values...), errors: map[string]string{},
	}
	model.route = routeSettings
	model.editor = editor
	editor.setFocus(0)
	editor.validate(model)
}

func (model *Model) openConsumerEditor(consumer *Consumer) {
	candidate := Consumer{}
	returnRoute := routeDashboard
	var consumerID *string
	if consumer != nil {
		candidate = *consumer
		candidate.Fingerprints = append([]string(nil), consumer.Fingerprints...)
		identifier := consumer.ID
		consumerID = &identifier
		returnRoute = routeConsumer
	}
	group := ""
	if candidate.AccessGroup != nil {
		group = strconv.FormatUint(uint64(*candidate.AccessGroup), 10)
	}
	values := []string{candidate.Name, candidate.Socket, group}
	inputs := []textinput.Model{input(values[0], 50), input(values[1], 80), input(values[2], 16)}
	editor := &editorState{
		kind: editConsumer, baseRevision: model.configuration.Revision, returnRoute: returnRoute,
		consumerID: consumerID, originalConsumer: candidate, inputs: inputs,
		originalValues: append([]string(nil), values...), originalSelected: append([]string(nil), candidate.Fingerprints...),
		fingerprints: fingerprintUnion(candidate.Fingerprints, model.offeredKeys()), errors: map[string]string{},
	}
	model.editor = editor
	editor.setFocus(0)
	editor.validate(model)
}

func (model *Model) offeredKeys() []Key {
	if model.keysState != loadReady && model.keysState != loadEmpty {
		return nil
	}
	return model.keys.Keys
}

func fingerprintUnion(configured []string, offered []Key) []fingerprintChoice {
	configuredSet := make(map[string]bool, len(configured))
	for _, fingerprint := range configured {
		configuredSet[fingerprint] = true
	}
	choices := make([]fingerprintChoice, 0, len(configured)+len(offered))
	seen := make(map[string]bool, len(configured)+len(offered))
	for _, key := range offered {
		if seen[key.Fingerprint] {
			continue
		}
		seen[key.Fingerprint] = true
		choices = append(choices, fingerprintChoice{
			Fingerprint: key.Fingerprint, Display: key.Display, Selected: configuredSet[key.Fingerprint], Offered: true,
		})
	}
	missing := make([]string, 0, len(configured))
	for _, fingerprint := range configured {
		if !seen[fingerprint] {
			missing = append(missing, fingerprint)
		}
	}
	sort.Strings(missing)
	for _, fingerprint := range missing {
		choices = append(choices, fingerprintChoice{Fingerprint: fingerprint, Selected: true})
	}
	return choices
}

func (editor *editorState) fieldCount() int { return len(editor.inputs) }

func (editor *editorState) fingerprintFocus() int {
	if editor.kind != editConsumer {
		return -1
	}
	return len(editor.inputs)
}

func (editor *editorState) browseFocus() int {
	if editor.kind != editUpstream {
		return -1
	}
	return len(editor.inputs)
}

func (editor *editorState) saveFocus() int {
	if editor.kind == editConsumer || editor.kind == editUpstream {
		return len(editor.inputs) + 1
	}
	return len(editor.inputs)
}

func (editor *editorState) cancelFocus() int { return editor.saveFocus() + 1 }
func (editor *editorState) focusCount() int  { return editor.cancelFocus() + 1 }

func (editor *editorState) setFocus(value int) {
	editor.focus = value
	for index := range editor.inputs {
		if index == value {
			editor.inputs[index].Focus()
		} else {
			editor.inputs[index].Blur()
		}
	}
}

func (editor *editorState) nextFocus(direction int, model *Model) {
	for attempts := 0; attempts < editor.focusCount(); attempts++ {
		next := (editor.focus + direction + editor.focusCount()) % editor.focusCount()
		editor.setFocus(next)
		if next != editor.saveFocus() || editor.canSave(model) {
			return
		}
	}
}

func (editor *editorState) selectedFingerprints() []string {
	selected := make([]string, 0, len(editor.fingerprints))
	for _, choice := range editor.fingerprints {
		if choice.Selected {
			selected = append(selected, choice.Fingerprint)
		}
	}
	sort.Strings(selected)
	return selected
}

func (editor *editorState) syncDirty() {
	values := make([]string, len(editor.inputs))
	for index := range editor.inputs {
		values[index] = editor.inputs[index].Value()
	}
	editor.dirty = !equalStrings(values, editor.originalValues) || !equalStrings(editor.selectedFingerprints(), sortedCopy(editor.originalSelected))
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func sortedCopy(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}

func (editor *editorState) canSave(model *Model) bool {
	return editor.dirty && !editor.conflict && !editor.saving && editor.validate(model)
}

func (editor *editorState) validate(model *Model) bool {
	editor.errors = map[string]string{}
	configuration, err := model.configCandidate()
	if err != nil {
		editor.errors["form"] = "configuration projection unavailable"
		return false
	}
	switch editor.kind {
	case editUpstream:
		configuration.Upstream = editor.inputs[0].Value()
	case editTimeouts:
		values := make([]time.Duration, 4)
		for index := range editor.inputs {
			value, parseErr := time.ParseDuration(editor.inputs[index].Value())
			if parseErr != nil || value <= 0 {
				editor.errors[timeoutName(index)] = "must be a positive Go duration"
				continue
			}
			values[index] = value
		}
		if len(editor.errors) > 0 {
			return false
		}
		configuration.Timeouts = config.Timeouts{Connect: values[0], List: values[1], Replay: values[2], Sign: values[3]}
	case editConsumer:
		consumer, consumerErr := editor.consumerCandidate()
		if consumerErr != nil {
			editor.errors["access-group"] = consumerErr.Error()
			return false
		}
		candidate := config.Consumer{Name: consumer.Name, Socket: consumer.Socket, AccessGroup: consumer.AccessGroup, Fingerprints: consumer.Fingerprints}
		if editor.consumerID == nil {
			configuration.Consumers = append(configuration.Consumers, candidate)
		} else {
			replaced := false
			for index, current := range model.consumers {
				if current.ID == *editor.consumerID {
					configuration.Consumers[index] = candidate
					replaced = true
					break
				}
			}
			if !replaced {
				editor.errors["form"] = "consumer is no longer configured"
				return false
			}
		}
	}
	if err := config.Validate(configuration); err != nil {
		var field *config.FieldError
		if errors.As(err, &field) {
			editor.errors[editorField(field.Field)] = sanitize(field.Problem)
		} else {
			editor.errors["form"] = "candidate is invalid"
		}
		return false
	}
	return true
}

func timeoutName(index int) string {
	return []string{"connect", "list", "replay", "sign"}[index]
}

func editorField(field string) string {
	for _, name := range []string{"connect", "list", "replay", "sign", "name", "socket", "access-group", "fingerprints", "upstream"} {
		if field == name || strings.HasSuffix(field, "."+name) {
			return name
		}
	}
	return "form"
}

func (model *Model) configCandidate() (config.Config, error) {
	connect, err := time.ParseDuration(model.configuration.Timeouts.Connect)
	if err != nil {
		return config.Config{}, err
	}
	listTimeout, err := time.ParseDuration(model.configuration.Timeouts.List)
	if err != nil {
		return config.Config{}, err
	}
	replay, err := time.ParseDuration(model.configuration.Timeouts.Replay)
	if err != nil {
		return config.Config{}, err
	}
	sign, err := time.ParseDuration(model.configuration.Timeouts.Sign)
	if err != nil {
		return config.Config{}, err
	}
	consumers := make([]config.Consumer, len(model.consumers))
	for index, consumer := range model.consumers {
		consumers[index] = config.Consumer{
			Name: consumer.Name, Socket: consumer.Socket, AccessGroup: consumer.AccessGroup,
			Fingerprints: append([]string(nil), consumer.Fingerprints...),
		}
	}
	return config.Config{
		Upstream: model.configuration.Upstream, Consumers: consumers,
		Timeouts: config.Timeouts{Connect: connect, List: listTimeout, Replay: replay, Sign: sign},
	}, nil
}

func (editor *editorState) timeoutCandidate() Timeouts {
	return Timeouts{
		Connect: editor.inputs[0].Value(), List: editor.inputs[1].Value(),
		Replay: editor.inputs[2].Value(), Sign: editor.inputs[3].Value(),
	}
}

func (editor *editorState) consumerCandidate() (Consumer, error) {
	var group *uint32
	if value := editor.inputs[2].Value(); value != "" {
		parsed, err := strconv.ParseUint(value, 10, 32)
		if err != nil || parsed == uint64(^uint32(0)) {
			return Consumer{}, errors.New("must be between 0 and 4294967294")
		}
		converted := uint32(parsed)
		group = &converted
	}
	return Consumer{
		ID: valueOrEmpty(editor.consumerID), Name: editor.inputs[0].Value(), Socket: editor.inputs[1].Value(),
		AccessGroup: group, Fingerprints: editor.selectedFingerprints(),
	}, nil
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (model *Model) updateEditorKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	editor := model.editor
	if editor.verifying {
		if key.String() == "ctrl+c" || key.String() == "q" {
			model.modal = modalExit
		}
		return model, nil
	}
	if editor.reloading {
		if key.String() == "ctrl+c" || key.String() == "q" {
			model.close()
			return model, tea.Quit
		}
		return model, nil
	}
	if editor.saving {
		if key.String() == "ctrl+c" || key.String() == "q" {
			model.modal = modalExit
		}
		return model, nil
	}
	switch key.String() {
	case "ctrl+c", "q":
		if editor.focus < editor.fieldCount() && key.String() == "q" {
			break
		}
		if editor.dirty {
			model.modal = modalExit
			return model, nil
		}
		model.close()
		return model, tea.Quit
	case "esc":
		if editor.dirty {
			model.modal = modalDiscard
		} else {
			model.closeEditor()
		}
		return model, nil
	case "tab":
		editor.nextFocus(1, model)
		return model, nil
	case "shift+tab":
		editor.nextFocus(-1, model)
		return model, nil
	case "R":
		if editor.conflict {
			editor.reloading = true
			return model, model.startRefresh(true, true)
		}
	case "up", "k":
		if editor.focus == editor.fingerprintFocus() && len(editor.fingerprints) > 0 {
			editor.fingerprintIndex = bounded(editor.fingerprintIndex-1, 0, len(editor.fingerprints)-1)
		}
		return model, nil
	case "down", "j":
		if editor.focus == editor.fingerprintFocus() && len(editor.fingerprints) > 0 {
			editor.fingerprintIndex = bounded(editor.fingerprintIndex+1, 0, len(editor.fingerprints)-1)
		}
		return model, nil
	case " ":
		if editor.focus == editor.fingerprintFocus() && len(editor.fingerprints) > 0 {
			choice := &editor.fingerprints[editor.fingerprintIndex]
			choice.Selected = !choice.Selected
			editor.syncDirty()
			editor.validate(model)
			return model, nil
		}
	case "enter":
		switch editor.focus {
		case editor.browseFocus():
			return model, model.startBrowse()
		case editor.saveFocus():
			return model, model.saveEditor()
		case editor.cancelFocus():
			if editor.dirty {
				model.modal = modalDiscard
			} else {
				model.closeEditor()
			}
			return model, nil
		}
	}
	if editor.focus < editor.fieldCount() {
		updated, command := editor.inputs[editor.focus].Update(key)
		editor.inputs[editor.focus] = updated
		editor.syncDirty()
		editor.failure = ""
		editor.validate(model)
		return model, command
	}
	return model, nil
}

func (model *Model) closeEditor() {
	if model.editor == nil {
		return
	}
	model.route = model.editor.returnRoute
	model.editor = nil
	model.browserState = browserViewState{}
}

func (model *Model) saveEditor() tea.Cmd {
	editor := model.editor
	if editor == nil || !editor.canSave(model) {
		return nil
	}
	editor.saving = true
	model.mutationInFlight = true
	model.request++
	request := model.request
	revision := editor.baseRevision
	switch editor.kind {
	case editUpstream:
		value := editor.inputs[0].Value()
		return func() tea.Msg {
			result, err := model.client.SetUpstream(model.ctx, revision, value)
			return mutationMsg{request: request, kind: editUpstream, result: result, err: err}
		}
	case editTimeouts:
		value := editor.timeoutCandidate()
		return func() tea.Msg {
			result, err := model.client.SetTimeouts(model.ctx, revision, value)
			return mutationMsg{request: request, kind: editTimeouts, result: result, err: err}
		}
	case editConsumer:
		value, _ := editor.consumerCandidate()
		identifier := editor.consumerID
		return func() tea.Msg {
			result, err := model.client.PutConsumer(model.ctx, revision, identifier, value)
			return mutationMsg{request: request, kind: editConsumer, result: result, err: err}
		}
	}
	return nil
}

func (model *Model) retireConsumer() tea.Cmd {
	consumer, ok := model.selectedConsumer()
	if !ok || model.configuration.Revision == "" {
		return nil
	}
	model.request++
	model.mutationInFlight = true
	model.setNotice("RETIRING · durable mutation in progress", false)
	request := model.request
	revision, identifier := model.configuration.Revision, consumer.ID
	return func() tea.Msg {
		result, err := model.client.RetireConsumer(model.ctx, revision, identifier)
		return mutationMsg{request: request, kind: editRetire, result: result, err: err}
	}
}

func (model *Model) updateMutation(message mutationMsg) (tea.Model, tea.Cmd) {
	if message.request != model.request {
		return model, nil
	}
	model.mutationInFlight = false
	if model.editor != nil {
		model.editor.saving = false
	}
	if message.err != nil {
		var remote *control.RemoteError
		if errors.As(message.err, &remote) {
			if remote.Code == control.ErrorConfigurationConflict && model.editor != nil {
				model.editor.conflict = true
				model.editor.failure = "CONFLICT"
				return model, nil
			}
			if remote.Code == control.ErrorConfigurationDurabilityUncertain {
				model.setNotice("CONFIGURATION COMMIT UNCERTAIN · VERIFYING DURABILITY", true)
				if model.editor != nil {
					model.editor.failure = model.notice
				}
				return model, model.startDurabilityVerification()
			}
			model.setNotice("SAVE REJECTED · "+strings.ToUpper(string(remote.Code)), false)
		} else {
			model.setNotice("SAVE DISCONNECTED", false)
		}
		if model.editor != nil {
			model.editor.failure = model.notice
		}
		return model, nil
	}
	model.configuration.Revision = message.result.Revision
	model.setNotice("SAVED · UNAPPLIED", false)
	if message.kind == editConsumer && message.result.ConsumerID != nil {
		model.selectionID = *message.result.ConsumerID
	}
	if message.kind == editRetire {
		model.route = routeDashboard
	} else {
		model.closeEditor()
	}
	return model, model.startRefresh(true, true)
}

func (model *Model) apply() tea.Cmd {
	if model.applyInFlight || model.configuration.Revision == "" {
		return nil
	}
	model.applyInFlight = true
	model.setNotice("APPLYING", false)
	model.request++
	request := model.request
	return func() tea.Msg {
		result, err := model.client.Apply(model.ctx)
		return applyMsg{request: request, result: result, err: err}
	}
}

func (model *Model) updateApply(message applyMsg) (tea.Model, tea.Cmd) {
	if message.request != model.request {
		return model, nil
	}
	model.applyInFlight = false
	if message.err != nil {
		var remote *control.RemoteError
		if errors.As(message.err, &remote) {
			model.setNotice("APPLY REJECTED · "+strings.ToUpper(string(remote.Code)), false)
		} else {
			model.setNotice("APPLY DISCONNECTED", false)
		}
		return model, nil
	}
	if !message.result.Committed {
		model.setNotice("APPLY REJECTED", false)
		return model, nil
	}
	if message.result.Degraded {
		model.setNotice(fmt.Sprintf("COMMITTED DEGRADED · cleanup %d · permissions %d", message.result.PendingCleanup, message.result.PendingPermissions), false)
	} else {
		model.setNotice("APPLIED · COMMITTED", false)
	}
	return model, model.startRefresh(true, true)
}

func (model *Model) startBrowse() tea.Cmd {
	if model.editor == nil || model.editor.kind != editUpstream {
		return nil
	}
	parent := filepath.Dir(model.editor.inputs[0].Value())
	model.request++
	request := model.request
	model.browserState = browserViewState{active: true, loading: true, parent: parent, state: loadLoading}
	return func() tea.Msg {
		listing, err := model.browser.Browse(model.ctx, parent)
		return browserMsg{request: request, parent: parent, listing: listing, err: err}
	}
}

func (model *Model) updateBrowser(message browserMsg) (tea.Model, tea.Cmd) {
	if message.request != model.request || !model.browserState.active {
		return model, nil
	}
	model.browserState.loading = false
	if message.err != nil {
		model.browserState.state = stateFor(message.err, 0)
		return model, nil
	}
	entries := append([]SocketEntry(nil), message.listing.Entries...)
	if len(entries) > maximumBrowserEntries {
		entries = entries[:maximumBrowserEntries]
	}
	model.browserState.entries = entries
	model.browserState.truncated = message.listing.Truncated || len(message.listing.Entries) > maximumBrowserEntries
	model.browserState.state = stateFor(nil, len(entries))
	model.browserState.index = 0
	return model, nil
}

func (model *Model) updateBrowserKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "ctrl+c", "q":
		model.browserState = browserViewState{}
		return model.updateEditorKey(tea.KeyMsg{Type: tea.KeyCtrlC})
	case "esc":
		model.browserState = browserViewState{}
	case "up", "k":
		model.browserState.index = bounded(model.browserState.index-1, 0, maximum(0, len(model.browserState.entries)-1))
	case "down", "j":
		model.browserState.index = bounded(model.browserState.index+1, 0, maximum(0, len(model.browserState.entries)-1))
	case "enter":
		if len(model.browserState.entries) == 0 {
			return model, nil
		}
		entry := model.browserState.entries[model.browserState.index]
		if entry.Directory {
			model.editor.inputs[0].SetValue(filepath.Join(entry.Path, filepath.Base(model.editor.inputs[0].Value())))
			return model, model.startBrowse()
		}
		if entry.Socket {
			model.editor.inputs[0].SetValue(entry.Path)
			model.editor.inputs[0].CursorEnd()
			model.editor.syncDirty()
			model.editor.validate(model)
			model.browserState = browserViewState{}
		}
	}
	return model, nil
}

func (model *Model) updateModal(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if model.modal == modalExit && key.String() == "ctrl+c" {
		model.close()
		return model, tea.Quit
	}
	switch key.String() {
	case "esc", "k":
		wasExit := model.modal == modalExit
		model.modal = modalNone
		if wasExit && model.resetInterrupt != nil {
			model.resetInterrupt()
		}
	case "d":
		modal := model.modal
		model.modal = modalNone
		if modal == modalExit {
			model.close()
			return model, tea.Quit
		}
		if modal == modalDiscard {
			model.closeEditor()
		}
	case "y":
		if model.modal == modalRetire {
			model.modal = modalNone
			return model, model.retireConsumer()
		}
	}
	return model, nil
}

func (model *Model) finishReloadEditor() {
	if model.editor == nil || !model.editor.reloading {
		return
	}
	kind := model.editor.kind
	identifier := model.editor.consumerID
	switch kind {
	case editUpstream:
		model.openUpstreamEditor()
	case editTimeouts:
		model.openTimeoutEditor()
	case editConsumer:
		if identifier != nil {
			for index := range model.consumers {
				if model.consumers[index].ID == *identifier {
					model.openConsumerEditor(&model.consumers[index])
					return
				}
			}
			model.editor = nil
			model.route = routeDashboard
			model.setNotice("RELOAD · CONSUMER NOT FOUND", false)
		} else {
			model.openConsumerEditor(nil)
		}
	}
}

func (model *Model) updateReloadConfiguration(message configurationMsg) (tea.Model, tea.Cmd) {
	editor := model.editor
	if message.err != nil {
		editor.reloading = false
		editor.failure = stateFor(message.err, 0).String() + " · candidate preserved"
		return model, model.settleRefreshOperation(refreshConfiguration)
	}
	if message.offset == 0 {
		editor.reloadConfiguration = message.page
		editor.reloadConsumers = append([]Consumer(nil), message.page.Consumers...)
	} else {
		if message.page.Revision != editor.reloadConfiguration.Revision {
			editor.reloading = false
			editor.failure = "UNAVAILABLE · configuration revision changed · candidate preserved"
			return model, model.settleRefreshOperation(refreshConfiguration)
		}
		editor.reloadConsumers = append(editor.reloadConsumers, message.page.Consumers...)
	}
	if len(editor.reloadConsumers) > message.page.TotalConsumers {
		editor.reloading = false
		editor.failure = "UNAVAILABLE · candidate preserved"
		return model, model.settleRefreshOperation(refreshConfiguration)
	}
	if message.page.NextOffset != nil {
		return model, model.loadConfiguration(message.generation, *message.page.NextOffset, message.page.Revision)
	}
	if len(editor.reloadConsumers) != message.page.TotalConsumers {
		editor.reloading = false
		editor.failure = "UNAVAILABLE · candidate preserved"
		return model, model.settleRefreshOperation(refreshConfiguration)
	}
	model.configuration = editor.reloadConfiguration
	model.consumers = append([]Consumer(nil), editor.reloadConsumers...)
	model.configurationState = stateFor(nil, len(model.consumers))
	model.setConsumerItems()
	model.finishReloadEditor()
	model.setNotice("", false)
	return model, model.settleRefreshOperation(refreshConfiguration)
}
