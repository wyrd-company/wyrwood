//go:build linux

// ---
// relationships:
//   implements: terminal-interface
//   uses: control-interface
// ---

package tui

import (
	"context"
	"errors"
	"time"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/muesli/termenv"
	"github.com/wyrd-company/wyrwood/internal/control"
)

const (
	referenceWidth  = 118
	referenceHeight = 34
	maximumWidth    = 240
	maximumHeight   = 80
	narrowWidth     = 60
	stackedWidth    = 96
	shortHeight     = 16
)

type route uint8

const (
	routeDashboard route = iota
	routeUpstream
	routeConsumer
	routeSettings
)

type loadState uint8

const (
	loadLoading loadState = iota
	loadReady
	loadEmpty
	loadUnavailable
	loadDisconnected
)

type focus uint8

const (
	focusUpstream focus = iota
	focusConsumers
	focusSummary
	focusCount
)

type scheduleFunc func(context.Context, time.Duration, uint64) tea.Cmd

type refreshOperation uint8

const (
	refreshConfiguration refreshOperation = 1 << iota
	refreshKeys
	refreshStatus
	refreshEvents
)

type options struct {
	Colors         bool
	ColorProfile   *termenv.Profile
	Schedule       scheduleFunc
	Browser        SocketBrowser
	ResetInterrupt func()
}

type consumerItem struct{ consumer Consumer }

func (item consumerItem) FilterValue() string { return item.consumer.Name }

// Model is the deterministic Bubble Tea state boundary. All external work is
// represented by commands that return the closed messages below.
type Model struct {
	client Client
	ctx    context.Context
	cancel context.CancelFunc

	generation       uint64
	refreshCtx       context.Context
	refreshCancel    context.CancelFunc
	pendingRefresh   refreshOperation
	refreshScheduled bool
	schedule         scheduleFunc

	width  int
	height int
	styles palette
	route  route
	focus  focus
	help   bool
	closed bool

	configurationState loadState
	keysState          loadState
	statusState        loadState
	eventsState        loadState
	configuration      ConfigurationPage
	consumers          []Consumer
	keys               Keys
	status             Status
	events             Events
	consumerList       list.Model

	editor           *editorState
	modal            modalKind
	browser          SocketBrowser
	browserState     browserViewState
	request          uint64
	mutationInFlight bool
	applyInFlight    bool
	notice           string
	noticeSticky     bool
	resetInterrupt   func()
	selectionID      string
}

type configurationMsg struct {
	generation uint64
	offset     int
	page       ConfigurationPage
	err        error
}

type keysMsg struct {
	generation uint64
	result     Keys
	err        error
}

type statusMsg struct {
	generation uint64
	result     Status
	err        error
}

type eventsMsg struct {
	generation uint64
	result     Events
	err        error
}

type tickMsg struct{ generation uint64 }

func NewModel(client Client, opts options) *Model {
	ctx, cancel := context.WithCancel(context.Background())
	if opts.Schedule == nil {
		opts.Schedule = schedule
	}
	if opts.Browser == nil {
		opts.Browser = linuxSocketBrowser{}
	}
	consumerList := list.New(nil, list.NewDefaultDelegate(), 1, 1)
	consumerList.SetShowTitle(false)
	consumerList.SetShowFilter(false)
	consumerList.SetFilteringEnabled(false)
	consumerList.SetShowStatusBar(false)
	consumerList.SetShowPagination(false)
	consumerList.SetShowHelp(false)
	consumerList.DisableQuitKeybindings()
	return &Model{
		client:             client,
		ctx:                ctx,
		cancel:             cancel,
		schedule:           opts.Schedule,
		browser:            opts.Browser,
		resetInterrupt:     opts.ResetInterrupt,
		styles:             newPalette(opts.Colors, opts.ColorProfile),
		width:              referenceWidth,
		height:             referenceHeight,
		focus:              focusConsumers,
		configurationState: loadLoading,
		keysState:          loadLoading,
		statusState:        loadLoading,
		eventsState:        loadLoading,
		consumerList:       consumerList,
	}
}

func (model *Model) Init() tea.Cmd {
	return model.startRefresh(true, true)
}

func (model *Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	if model.closed {
		return model, nil
	}
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		model.width = bounded(message.Width, 1, maximumWidth)
		model.height = bounded(message.Height, 1, maximumHeight)
		model.consumerList.SetSize(maximum(1, model.width/2), maximum(1, model.height-12))
		return model, nil
	case tea.KeyMsg:
		return model.updateKey(message)
	case configurationMsg:
		return model.updateConfiguration(message)
	case keysMsg:
		if message.generation == model.generation {
			model.keysState = stateFor(message.err, len(message.result.Keys))
			if message.err == nil {
				model.keys = message.result
				if model.editor != nil && model.editor.kind == editConsumer {
					selected := model.editor.selectedFingerprints()
					model.editor.fingerprints = fingerprintUnion(selected, message.result.Keys)
					model.editor.fingerprintIndex = bounded(model.editor.fingerprintIndex, 0, maximum(0, len(model.editor.fingerprints)-1))
					model.editor.syncDirty()
					model.editor.validate(model)
				}
			}
			return model, model.settleRefreshOperation(refreshKeys)
		}
	case statusMsg:
		if message.generation == model.generation {
			model.statusState = stateFor(message.err, 1)
			if message.err == nil {
				model.status = message.result
			}
			return model, model.settleRefreshOperation(refreshStatus)
		}
	case eventsMsg:
		if message.generation == model.generation {
			model.eventsState = stateFor(message.err, len(message.result.Events))
			if message.err == nil {
				model.events = message.result
			}
			return model, model.settleRefreshOperation(refreshEvents)
		}
	case tickMsg:
		if message.generation == model.generation && model.pendingRefresh == 0 {
			return model, model.startRefresh(false, false)
		}
	case mutationMsg:
		return model.updateMutation(message)
	case applyMsg:
		return model.updateApply(message)
	case browserMsg:
		return model.updateBrowser(message)
	}
	return model, nil
}

func (model *Model) updateKey(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if !model.mutationInFlight && !model.applyInFlight {
		model.clearTransientNotice()
	}
	if model.modal != modalNone {
		return model.updateModal(key)
	}
	if model.browserState.active {
		return model.updateBrowserKey(key)
	}
	if model.editor != nil {
		return model.updateEditorKey(key)
	}
	if model.mutationInFlight || model.applyInFlight {
		if key.String() == "ctrl+c" || key.String() == "q" {
			model.close()
			return model, tea.Quit
		}
		return model, nil
	}
	switch key.String() {
	case "ctrl+c", "q":
		model.close()
		return model, tea.Quit
	case "?":
		model.help = !model.help
	case "esc":
		if model.help {
			model.help = false
		} else if model.route != routeDashboard {
			model.route = routeDashboard
			model.focus = focusConsumers
		}
	case "tab":
		if model.route == routeDashboard {
			model.focus = (model.focus + 1) % focusCount
		}
	case "shift+tab":
		if model.route == routeDashboard {
			model.focus = (model.focus + focusCount - 1) % focusCount
		}
	case "enter":
		if model.route == routeDashboard && model.focus == focusUpstream {
			model.route = routeUpstream
		} else if model.route == routeDashboard && model.focus == focusConsumers {
			if _, ok := model.selectedConsumer(); ok {
				model.route = routeConsumer
			}
		}
	case "e":
		if model.route == routeUpstream && model.configurationUsable() {
			model.openUpstreamEditor()
		} else if model.route == routeConsumer && model.configurationUsable() {
			if consumer, ok := model.selectedConsumer(); ok {
				model.openConsumerEditor(&consumer)
			}
		}
	case "n":
		if model.route == routeDashboard && model.configurationUsable() {
			model.openConsumerEditor(nil)
		}
	case "x":
		if model.route == routeConsumer && model.configurationUsable() {
			if _, ok := model.selectedConsumer(); ok {
				model.modal = modalRetire
			}
		}
	case "s":
		if model.route != routeSettings && model.configurationUsable() {
			model.openTimeoutEditor()
		}
	case "a":
		if model.configurationUsable() {
			return model, model.apply()
		}
	case "r":
		return model, model.startRefresh(true, true)
	case "up", "k", "down", "j":
		if model.route == routeDashboard && model.focus == focusConsumers && len(model.consumers) > 0 {
			updated, command := model.consumerList.Update(key)
			model.consumerList = updated
			return model, command
		}
	}
	return model, nil
}

func (model *Model) configurationUsable() bool {
	return (model.configurationState == loadReady || model.configurationState == loadEmpty) && model.configuration.Revision != ""
}

func (model *Model) updateConfiguration(message configurationMsg) (tea.Model, tea.Cmd) {
	if message.generation != model.generation {
		return model, nil
	}
	if model.editor != nil && model.editor.verifying {
		return model.updateVerificationConfiguration(message)
	}
	if model.editor != nil && model.editor.reloading {
		return model.updateReloadConfiguration(message)
	}
	if message.err != nil {
		if model.editor != nil && model.editor.dirty {
			var remote *control.RemoteError
			if errors.As(message.err, &remote) && remote.Code == control.ErrorConfigurationConflict {
				model.editor.conflict = true
				model.editor.failure = "CONFLICT"
			} else {
				model.editor.failure = stateFor(message.err, 0).String() + " · candidate preserved"
			}
			return model, model.settleRefreshOperation(refreshConfiguration)
		}
		model.configurationState = stateFor(message.err, 0)
		model.consumers = nil
		model.setConsumerItems()
		return model, model.settleRefreshOperation(refreshConfiguration)
	}
	if message.offset == 0 && model.editor != nil && model.editor.dirty && !model.editor.reloading {
		if message.page.Revision != model.editor.baseRevision {
			model.editor.conflict = true
			model.editor.failure = "CONFLICT"
		}
		model.configurationState = stateFor(nil, len(model.consumers))
		return model, model.settleRefreshOperation(refreshConfiguration)
	}
	if model.editor != nil && !model.editor.dirty {
		// A configuration response received while a clean editor is open must
		// always be buffered as a complete coherent reload. This defensive path
		// prevents a future caller from committing a page-zero projection while
		// the remaining pages are still absent.
		model.editor.reloading = true
		model.editor.reloadConfiguration = ConfigurationPage{}
		model.editor.reloadConsumers = nil
		return model.updateReloadConfiguration(message)
	}
	if message.offset == 0 {
		model.configuration = message.page
		model.consumers = append([]Consumer(nil), message.page.Consumers...)
	} else {
		if message.page.Revision != model.configuration.Revision {
			model.configurationState = loadUnavailable
			model.consumers = nil
			model.setConsumerItems()
			return model, model.settleRefreshOperation(refreshConfiguration)
		}
		model.consumers = append(model.consumers, message.page.Consumers...)
	}
	if len(model.consumers) > message.page.TotalConsumers {
		model.configurationState = loadUnavailable
		model.consumers = nil
		model.setConsumerItems()
		return model, model.settleRefreshOperation(refreshConfiguration)
	}
	if message.page.NextOffset != nil {
		return model, model.loadConfiguration(message.generation, *message.page.NextOffset, message.page.Revision)
	}
	if len(model.consumers) != message.page.TotalConsumers {
		model.configurationState = loadUnavailable
		model.consumers = nil
		model.setConsumerItems()
		return model, model.settleRefreshOperation(refreshConfiguration)
	}
	model.configurationState = stateFor(nil, len(model.consumers))
	model.setConsumerItems()
	model.finishReloadEditor()
	return model, model.settleRefreshOperation(refreshConfiguration)
}

func (model *Model) startRefresh(includeConfiguration, includeKeys bool) tea.Cmd {
	if model.refreshCancel != nil {
		model.refreshCancel()
	}
	model.generation++
	generation := model.generation
	refreshContext, cancel := context.WithCancel(model.ctx)
	model.refreshCtx = refreshContext
	model.refreshCancel = cancel
	model.pendingRefresh = refreshStatus | refreshEvents
	model.refreshScheduled = false
	model.statusState = loadLoading
	model.eventsState = loadLoading
	commands := []tea.Cmd{
		model.loadStatus(refreshContext, generation),
		model.loadEvents(refreshContext, generation),
	}
	if includeConfiguration {
		model.pendingRefresh |= refreshConfiguration
		if model.editor != nil && !model.editor.dirty {
			model.editor.reloading = true
		}
		if model.editor == nil {
			model.configurationState = loadLoading
			model.consumers = nil
			model.setConsumerItems()
		}
		commands = append(commands, model.loadConfigurationWithContext(refreshContext, generation, 0, ""))
	}
	if includeKeys {
		model.pendingRefresh |= refreshKeys
		model.keysState = loadLoading
		commands = append(commands, model.loadKeys(refreshContext, generation))
	}
	return tea.Batch(commands...)
}

func (model *Model) loadConfiguration(generation uint64, offset int, revision string) tea.Cmd {
	return model.loadConfigurationWithContext(model.currentRefreshContext(), generation, offset, revision)
}

func (model *Model) loadConfigurationWithContext(ctx context.Context, generation uint64, offset int, revision string) tea.Cmd {
	return func() tea.Msg {
		page, err := model.client.Configuration(ctx, offset, configurationPageSize, revision)
		return configurationMsg{generation: generation, offset: offset, page: page, err: err}
	}
}

func (model *Model) loadKeys(ctx context.Context, generation uint64) tea.Cmd {
	return func() tea.Msg {
		keys, err := model.client.Keys(ctx)
		return keysMsg{generation: generation, result: keys, err: err}
	}
}

func (model *Model) loadStatus(ctx context.Context, generation uint64) tea.Cmd {
	return func() tea.Msg {
		status, err := model.client.Status(ctx)
		return statusMsg{generation: generation, result: status, err: err}
	}
}

func (model *Model) loadEvents(ctx context.Context, generation uint64) tea.Cmd {
	return func() tea.Msg {
		events, err := model.client.Events(ctx, eventLimit)
		return eventsMsg{generation: generation, result: events, err: err}
	}
}

func (model *Model) scheduleWhenSettled() tea.Cmd {
	if model.pendingRefresh != 0 || model.closed || model.refreshScheduled {
		return nil
	}
	model.refreshScheduled = true
	return model.schedule(model.currentRefreshContext(), refreshInterval, model.generation)
}

func (model *Model) settleRefreshOperation(operation refreshOperation) tea.Cmd {
	model.pendingRefresh &^= operation
	return model.scheduleWhenSettled()
}

func (model *Model) currentRefreshContext() context.Context {
	if model.refreshCtx == nil {
		return model.ctx
	}
	return model.refreshCtx
}

func schedule(ctx context.Context, delay time.Duration, generation uint64) tea.Cmd {
	return func() tea.Msg {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil
		case <-timer.C:
			return tickMsg{generation: generation}
		}
	}
}

func (model *Model) setConsumerItems() {
	selectedID := model.selectionID
	if selected, ok := model.consumerList.SelectedItem().(consumerItem); ok {
		selectedID = selected.consumer.ID
	}
	items := make([]list.Item, len(model.consumers))
	selectedIndex := 0
	for index, consumer := range model.consumers {
		items[index] = consumerItem{consumer: consumer}
		if consumer.ID == selectedID {
			selectedIndex = index
			model.selectionID = ""
		}
	}
	model.consumerList.SetItems(items)
	model.consumerList.Select(selectedIndex)
}

func (model *Model) selectedConsumer() (Consumer, bool) {
	selected, ok := model.consumerList.SelectedItem().(consumerItem)
	return selected.consumer, ok
}

func (model *Model) close() {
	if model.closed {
		return
	}
	model.closed = true
	if model.refreshCancel != nil {
		model.refreshCancel()
	}
	model.cancel()
}

func stateFor(err error, count int) loadState {
	if err == nil {
		if count == 0 {
			return loadEmpty
		}
		return loadReady
	}
	if errors.Is(err, context.Canceled) {
		return loadLoading
	}
	var remote *control.RemoteError
	if errors.As(err, &remote) {
		return loadUnavailable
	}
	return loadDisconnected
}

func (state loadState) String() string {
	switch state {
	case loadLoading:
		return "LOADING"
	case loadReady:
		return "READY"
	case loadEmpty:
		return "EMPTY"
	case loadDisconnected:
		return "DISCONNECTED"
	default:
		return "UNAVAILABLE"
	}
}

func bounded(value, low, high int) int {
	return minimum(maximum(value, low), high)
}

func minimum(left, right int) int {
	if left < right {
		return left
	}
	return right
}

func maximum(left, right int) int {
	if left > right {
		return left
	}
	return right
}
