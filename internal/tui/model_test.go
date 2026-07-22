//go:build linux

// ---
// relationships:
//   verifies: terminal-interface
// ---

package tui

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/wyrd-company/wyrwood/internal/control"
)

var updateGolden = flag.Bool("update", false, "update golden render files")

const sampleFingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

type fakeClient struct {
	mu                 sync.Mutex
	configurationPages map[int]ConfigurationPage
	configurationErr   error
	keys               Keys
	keysErr            error
	status             Status
	statusErr          error
	events             Events
	eventsErr          error
	calls              []string
}

func (client *fakeClient) Configuration(ctx context.Context, offset, limit int, revision string) (ConfigurationPage, error) {
	client.record("configuration")
	if err := ctx.Err(); err != nil {
		return ConfigurationPage{}, err
	}
	if client.configurationErr != nil {
		return ConfigurationPage{}, client.configurationErr
	}
	return client.configurationPages[offset], nil
}

func (client *fakeClient) Keys(ctx context.Context) (Keys, error) {
	client.record("keys")
	if err := ctx.Err(); err != nil {
		return Keys{}, err
	}
	return client.keys, client.keysErr
}

func (client *fakeClient) Status(ctx context.Context) (Status, error) {
	client.record("status")
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	return client.status, client.statusErr
}

func (client *fakeClient) Events(ctx context.Context, limit int) (Events, error) {
	client.record("events")
	if err := ctx.Err(); err != nil {
		return Events{}, err
	}
	return client.events, client.eventsErr
}

func (client *fakeClient) record(call string) {
	client.mu.Lock()
	defer client.mu.Unlock()
	client.calls = append(client.calls, call)
}

func populatedClient() *fakeClient {
	consumerA := strings.Repeat("a", 64)
	consumerB := strings.Repeat("b", 64)
	next := 1
	return &fakeClient{
		configurationPages: map[int]ConfigurationPage{
			0: {
				Revision:       strings.Repeat("1", 64),
				Upstream:       "/tmp/example/source.sock",
				Timeouts:       Timeouts{Connect: "1s", List: "2s", Replay: "3s", Sign: "4s"},
				TotalConsumers: 2,
				Consumers: []Consumer{{
					ID: consumerA, Name: "sample alpha", Socket: "/tmp/example/alpha.sock", Fingerprints: []string{sampleFingerprint},
				}},
				NextOffset: &next,
			},
			1: {
				Revision:       strings.Repeat("1", 64),
				TotalConsumers: 2,
				Consumers: []Consumer{{
					ID: consumerB, Name: "sample beta", Socket: "/tmp/example/beta.sock", Fingerprints: []string{sampleFingerprint, "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"},
				}},
			},
		},
		keys: Keys{Keys: []Key{{Fingerprint: sampleFingerprint, Display: "sample primary"}, {Fingerprint: "SHA256:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA", Display: "sample alternate"}}},
		status: Status{
			ActiveRevision: strings.Repeat("0", 64),
			Daemon:         HealthHealthy,
			Upstream:       HealthDegraded,
			Consumers: []ConsumerStatus{
				{ID: consumerA, Name: "sample alpha", Listener: HealthHealthy, ActiveConnections: 2},
			},
			Truncated: true,
		},
		events: Events{Events: []Event{
			{Timestamp: time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC), ConsumerID: consumerA, Operation: "sign", Outcome: "succeeded", ErrorCode: "none"},
			{Timestamp: time.Date(2026, 2, 3, 4, 6, 7, 0, time.UTC), Operation: "upstream-connect", Outcome: "failed", ErrorCode: "upstream-unavailable"},
			{Timestamp: time.Date(2026, 2, 3, 4, 7, 8, 0, time.UTC), Operation: "replay", Outcome: "succeeded", ErrorCode: "none"},
		}},
	}
}

func readyModel(t *testing.T, colors bool) *Model {
	t.Helper()
	client := populatedClient()
	model := NewModel(client, options{Colors: colors, Schedule: noSchedule})
	model.Init()
	generation := model.generation
	_, command := model.Update(configurationMsg{generation: generation, offset: 0, page: client.configurationPages[0]})
	if command == nil {
		t.Fatal("first configuration page did not request its successor")
	}
	message := command()
	model.Update(message)
	model.Update(keysMsg{generation: generation, result: client.keys})
	model.Update(statusMsg{generation: generation, result: client.status})
	model.Update(eventsMsg{generation: generation, result: client.events})
	return model
}

func noSchedule(context.Context, time.Duration, uint64) tea.Cmd { return nil }

func debugState(model *Model) string {
	return fmt.Sprintf("route=%d focus=%d generation=%d consumers=%d", model.route, model.focus, model.generation, len(model.consumers))
}

func TestModelLoadsCoherentConfigurationPages(t *testing.T) {
	client := populatedClient()
	model := NewModel(client, options{Schedule: noSchedule})
	model.Init()
	generation := model.generation

	_, command := model.Update(configurationMsg{generation: generation, offset: 0, page: client.configurationPages[0]})
	if command == nil {
		t.Fatal("next page command is nil")
	}
	model.Update(command())
	if model.configurationState != loadReady || len(model.consumers) != 2 || model.consumerList.Items() == nil {
		t.Fatalf("configuration load = state %s, consumers %d", model.configurationState, len(model.consumers))
	}
}

func TestInitLoadsEveryProjectionThroughTheInjectedClient(t *testing.T) {
	client := populatedClient()
	model := NewModel(client, options{Schedule: noSchedule})
	commands := []tea.Cmd{model.Init()}
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
	if model.configurationState != loadReady || model.keysState != loadReady || model.statusState != loadReady || model.eventsState != loadReady {
		t.Fatalf("startup states = config %s, keys %s, status %s, events %s", model.configurationState, model.keysState, model.statusState, model.eventsState)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	wantCounts := map[string]int{"configuration": 2, "keys": 1, "status": 1, "events": 1}
	gotCounts := map[string]int{}
	for _, call := range client.calls {
		gotCounts[call]++
	}
	if !reflect.DeepEqual(gotCounts, wantCounts) {
		t.Fatalf("startup calls = %#v, want %#v", gotCounts, wantCounts)
	}
}

func TestModelRejectsIncompletePagination(t *testing.T) {
	model := NewModel(populatedClient(), options{Schedule: noSchedule})
	model.Init()
	model.Update(configurationMsg{generation: model.generation, page: ConfigurationPage{TotalConsumers: 2, Consumers: []Consumer{{ID: "unit"}}}})
	if model.configurationState != loadUnavailable || len(model.consumers) != 0 {
		t.Fatalf("incomplete page = state %s, consumers %d", model.configurationState, len(model.consumers))
	}
}

func TestStaleResultsDoNotUpdateTheModel(t *testing.T) {
	model := NewModel(populatedClient(), options{Schedule: noSchedule})
	model.Init()
	staleGeneration := model.generation
	model.startRefresh(true, true)
	model.Update(statusMsg{generation: staleGeneration, result: Status{Upstream: HealthHealthy}})
	if model.status.Upstream != "" || model.statusState != loadLoading {
		t.Fatalf("stale result changed model: %#v", model.status)
	}
}

func TestRefreshSchedulesOnlyAfterBothBackgroundLoadsSettle(t *testing.T) {
	scheduled := 0
	scheduler := func(context.Context, time.Duration, uint64) tea.Cmd {
		scheduled++
		return func() tea.Msg { return tickMsg{} }
	}
	model := NewModel(populatedClient(), options{Schedule: scheduler})
	model.startRefresh(false, false)
	generation := model.generation
	_, command := model.Update(statusMsg{generation: generation, result: Status{}})
	if command != nil || scheduled != 0 {
		t.Fatalf("scheduled before events settled: %d", scheduled)
	}
	model.Update(statusMsg{generation: generation, result: Status{}})
	if scheduled != 0 {
		t.Fatalf("duplicate status completion settled another operation: %d", scheduled)
	}
	_, command = model.Update(eventsMsg{generation: generation, result: Events{}})
	if command == nil || scheduled != 1 {
		t.Fatalf("settled refresh schedule = (%v, %d)", command, scheduled)
	}
	model.Update(eventsMsg{generation: generation, result: Events{}})
	if scheduled != 1 {
		t.Fatalf("duplicate completion should be ignored by lifecycle, schedules %d", scheduled)
	}
}

func TestRefreshWaitsForPaginatedConfigurationAndKeysBeforeScheduling(t *testing.T) {
	scheduled := 0
	scheduler := func(context.Context, time.Duration, uint64) tea.Cmd {
		scheduled++
		return func() tea.Msg { return tickMsg{} }
	}
	client := populatedClient()
	model := NewModel(client, options{Schedule: scheduler})
	model.Init()
	generation := model.generation

	_, nextPage := model.Update(configurationMsg{generation: generation, offset: 0, page: client.configurationPages[0]})
	if nextPage == nil {
		t.Fatal("first configuration page did not request its successor")
	}
	model.Update(keysMsg{generation: generation, result: client.keys})
	model.Update(statusMsg{generation: generation, result: client.status})
	_, command := model.Update(eventsMsg{generation: generation, result: client.events})
	if command != nil || scheduled != 0 || model.pendingRefresh != 1 {
		t.Fatalf("partial refresh = command %v, schedules %d, pending %d", command, scheduled, model.pendingRefresh)
	}

	model.Update(tickMsg{generation: generation})
	if model.generation != generation || model.configurationState != loadLoading {
		t.Fatalf("early tick replaced partial refresh: generation %d, configuration %s", model.generation, model.configurationState)
	}

	_, command = model.Update(nextPage())
	if command == nil || scheduled != 1 || model.pendingRefresh != 0 || model.configurationState != loadReady {
		t.Fatalf("completed refresh = command %v, schedules %d, pending %d, configuration %s", command, scheduled, model.pendingRefresh, model.configurationState)
	}
}

func TestRealSchedulerReturnsTickOrStopsOnCancellation(t *testing.T) {
	message := schedule(context.Background(), 0, 7)()
	if tick, ok := message.(tickMsg); !ok || tick.generation != 7 {
		t.Fatalf("scheduled message = %#v", message)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if message := schedule(ctx, time.Hour, 8)(); message != nil {
		t.Fatalf("canceled schedule returned %#v", message)
	}
}

func TestCloseCancelsInFlightEffectsAndIgnoresFurtherMessages(t *testing.T) {
	client := &blockingClient{started: make(chan struct{})}
	model := NewModel(client, options{Schedule: noSchedule})
	model.Init()
	command := model.loadStatus(model.currentRefreshContext(), model.generation)
	finished := make(chan tea.Msg, 1)
	go func() { finished <- command() }()
	<-client.started
	model.Update(tea.KeyMsg{Type: tea.KeyCtrlC})
	select {
	case message := <-finished:
		if result := message.(statusMsg); !errors.Is(result.err, context.Canceled) {
			t.Fatalf("in-flight result error = %v", result.err)
		}
	case <-time.After(time.Second):
		t.Fatal("in-flight effect did not stop after close")
	}
	before := model.status
	model.Update(statusMsg{generation: model.generation, result: Status{Upstream: HealthHealthy}})
	if !reflect.DeepEqual(model.status, before) || !model.closed {
		t.Fatalf("closed model accepted update: %s", debugState(model))
	}
}

type blockingClient struct{ started chan struct{} }

func (*blockingClient) Configuration(context.Context, int, int, string) (ConfigurationPage, error) {
	return ConfigurationPage{}, nil
}
func (*blockingClient) Keys(context.Context) (Keys, error) { return Keys{}, nil }
func (client *blockingClient) Status(ctx context.Context) (Status, error) {
	close(client.started)
	<-ctx.Done()
	return Status{}, ctx.Err()
}
func (*blockingClient) Events(context.Context, int) (Events, error) { return Events{}, nil }

func TestNavigationFocusHelpResizeAndCleanExit(t *testing.T) {
	model := readyModel(t, false)
	if model.focus != focusConsumers {
		t.Fatalf("initial focus = %d", model.focus)
	}
	model.Update(tea.KeyMsg{Type: tea.KeyDown})
	selectedBefore := model.consumerList.Index()
	model.Update(tea.WindowSizeMsg{Width: 58, Height: 14})
	if model.consumerList.Index() != selectedBefore || model.route != routeDashboard {
		t.Fatalf("resize changed selection or route: %s", debugState(model))
	}
	model.focus = focusUpstream
	model.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if model.route != routeUpstream {
		t.Fatal("enter did not open upstream route")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'?'}})
	if !model.help {
		t.Fatal("help did not expand")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if model.help || model.route != routeUpstream {
		t.Fatal("escape did not dismiss help first")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyEsc})
	if model.route != routeDashboard {
		t.Fatal("escape did not return to dashboard")
	}
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	if !model.closed || model.View() != "" {
		t.Fatal("quit did not close cleanly")
	}
}

func TestCategoricalFailureStatesAndRetry(t *testing.T) {
	model := NewModel(populatedClient(), options{Schedule: noSchedule})
	model.Init()
	generation := model.generation
	model.Update(configurationMsg{generation: generation, err: &control.RemoteError{Code: control.ErrorUnsupportedVersion}})
	model.Update(keysMsg{generation: generation, err: &control.RemoteError{Code: control.ErrorResourceLimit}})
	model.Update(statusMsg{generation: generation, err: errors.New("private marker")})
	model.Update(eventsMsg{generation: generation, result: Events{}})
	view := model.View()
	for _, label := range []string{"UNAVAILABLE", "DISCONNECTED", "r RETRY"} {
		if !strings.Contains(view, label) {
			t.Fatalf("failure view lacks %q:\n%s", label, view)
		}
	}
	if strings.Contains(view, "private marker") {
		t.Fatal("raw error reached rendering")
	}
	priorGeneration := model.generation
	model.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'r'}})
	if model.generation != priorGeneration+1 {
		t.Fatal("retry did not create a new request generation")
	}
}

func TestDisconnectedStatusDoesNotRenderStaleHealthyOrRevisionState(t *testing.T) {
	model := readyModel(t, false)
	readyView := model.View()
	if !strings.Contains(readyView, "UNAPPLIED") || !strings.Contains(readyView, "HEALTHY") {
		t.Fatalf("ready fixture lacks expected state:\n%s", readyView)
	}

	model.Update(statusMsg{generation: model.generation, err: errors.New("connection lost")})
	view := model.View()
	for _, stale := range []string{"UNAPPLIED", "ACTIVE", "HEALTHY", "STATUS INCOMPLETE"} {
		if strings.Contains(view, stale) {
			t.Fatalf("disconnected view retained %q:\n%s", stale, view)
		}
	}
	if !strings.Contains(view, "DISCONNECTED") || !strings.Contains(view, "STATUS NOT PROJECTED") {
		t.Fatalf("disconnected state not rendered explicitly:\n%s", view)
	}
}

func TestDeniedEventUsesTextMarkerWithoutColor(t *testing.T) {
	model := readyModel(t, false)
	consumer, ok := model.selectedConsumer()
	if !ok {
		t.Fatal("fixture has no selected consumer")
	}
	model.events = Events{Events: []Event{{
		Timestamp:  time.Date(2026, 2, 3, 4, 8, 9, 0, time.UTC),
		ConsumerID: consumer.ID,
		Operation:  "sign",
		Outcome:    "denied",
	}}}
	view := model.View()
	if !strings.Contains(view, "[!] sign") || !strings.Contains(view, "denied") || strings.Contains(view, "\x1b[") {
		t.Fatalf("denied event is not text-identifiable without color:\n%s", view)
	}
}

func TestDashboardFooterAdvertisesOnlyCurrentActions(t *testing.T) {
	model := readyModel(t, false)
	model.focus = focusUpstream
	if footer := model.footer(model.styles); !strings.Contains(footer, "enter Upstream") {
		t.Fatalf("upstream footer lacks its action: %q", footer)
	}
	model.focus = focusConsumers
	if footer := model.footer(model.styles); strings.Contains(footer, "enter") || !strings.Contains(footer, "Select") {
		t.Fatalf("consumer footer advertises unavailable action: %q", footer)
	}
	model.focus = focusSummary
	if footer := model.footer(model.styles); strings.Contains(footer, "enter") || strings.Contains(footer, "Select") {
		t.Fatalf("summary footer advertises unavailable action: %q", footer)
	}
}

func TestConsumerRowsAlignWideNamesByDisplayWidth(t *testing.T) {
	model := readyModel(t, false)
	model.consumers[0].Name = strings.Repeat("界", 20)
	model.setConsumerItems()
	rows := strings.Split(model.consumerRows(model.styles, 10), "\n")
	if len(rows) < 3 || !strings.Contains(rows[1], "…") {
		t.Fatalf("wide consumer name was not display-truncated: %#v", rows)
	}
	for _, row := range rows[1:3] {
		separator := strings.LastIndex(row, " ")
		if separator < 0 || ansi.StringWidth(row[:separator]) != 48 {
			t.Fatalf("connections column is not aligned by display width (%d): %q", ansi.StringWidth(row[:maximum(0, separator)]), row)
		}
	}
	model.Update(tea.WindowSizeMsg{Width: 118, Height: 34})
	for _, line := range strings.Split(model.View(), "\n") {
		if ansi.StringWidth(line) > 118 {
			t.Fatalf("wide-name view exceeded terminal width: %q", line)
		}
	}
}

func TestRenderingSanitizesControlAndBidiCharacters(t *testing.T) {
	model := readyModel(t, false)
	model.consumers[0].Name = "unsafe\x1b[31m\nname\u202e"
	model.setConsumerItems()
	view := model.View()
	if strings.Contains(view, "\x1b[31m") || strings.Contains(view, "\nname") || strings.ContainsRune(view, '\u202e') {
		t.Fatalf("untrusted controls reached view: %q", view)
	}
	if !strings.Contains(view, "unsafe�[31m�name�") {
		t.Fatalf("sanitized value not represented explicitly: %q", view)
	}
}

func TestSelectedConsumerSummaryIncludesConfiguredFingerprintIdentities(t *testing.T) {
	model := readyModel(t, false)
	view := model.View()
	if !strings.Contains(view, "SHA256:AAAAAAAAAAAA…") {
		t.Fatalf("selected summary omits configured fingerprint identity:\n%s", view)
	}
}

func TestViewsAreBoundedToTerminalDimensions(t *testing.T) {
	model := readyModel(t, true)
	for _, size := range []tea.WindowSizeMsg{{Width: 118, Height: 34}, {Width: 58, Height: 14}, {Width: 10000, Height: 10000}, {Width: 1, Height: 1}} {
		model.Update(size)
		view := model.View()
		lines := strings.Split(view, "\n")
		wantWidth := bounded(size.Width, 1, maximumWidth)
		wantHeight := bounded(size.Height, 1, maximumHeight)
		if len(lines) > wantHeight {
			t.Fatalf("size %#v rendered %d lines", size, len(lines))
		}
		for _, line := range lines {
			if width := printableWidth(line); width > wantWidth {
				t.Fatalf("size %#v rendered line width %d: %q", size, width, line)
			}
		}
	}
}

func TestDashboardAndUpstreamGoldens(t *testing.T) {
	tests := []struct {
		name   string
		colors bool
		route  route
		width  int
		height int
	}{
		{name: "dashboard-reference", route: routeDashboard, width: 118, height: 34},
		{name: "dashboard-narrow", route: routeDashboard, width: 58, height: 14},
		{name: "upstream-reference", route: routeUpstream, width: 118, height: 34},
		{name: "upstream-narrow", route: routeUpstream, width: 58, height: 14},
		{name: "dashboard-reference-color", colors: true, route: routeDashboard, width: 118, height: 34},
		{name: "dashboard-narrow-color", colors: true, route: routeDashboard, width: 58, height: 14},
		{name: "upstream-reference-color", colors: true, route: routeUpstream, width: 118, height: 34},
		{name: "upstream-narrow-color", colors: true, route: routeUpstream, width: 58, height: 14},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			model := readyModel(t, test.colors)
			model.route = test.route
			model.Update(tea.WindowSizeMsg{Width: test.width, Height: test.height})
			got := goldenValue(model.View(), test.colors)
			path := filepath.Join("testdata", test.name+".golden")
			if *updateGolden {
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal([]byte(got), want) {
				t.Fatalf("render differs from %s; run go test ./internal/tui -run TestDashboardAndUpstreamGoldens -update", path)
			}
		})
	}
}

func goldenValue(view string, colors bool) string {
	if colors {
		return strconv.Quote(view) + "\n"
	}
	lines := strings.Split(view, "\n")
	for index := range lines {
		lines[index] = strings.TrimRight(lines[index], " ")
	}
	return strings.Join(lines, "\n") + "\n"
}

func TestRunRefusesNonTerminalBeforeWriting(t *testing.T) {
	var output bytes.Buffer
	err := Run(strings.NewReader(""), &output, populatedClient())
	if !errors.Is(err, ErrNotTerminal) || output.Len() != 0 {
		t.Fatalf("Run = (%v, %q)", err, output.String())
	}
}

func printableWidth(value string) int {
	return ansi.StringWidth(value)
}
