//go:build linux

// ---
// relationships:
//   implements: terminal-interface
// ---

package tui

import (
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/muesli/termenv"
)

type palette struct {
	base      lipgloss.Style
	muted     lipgloss.Style
	healthy   lipgloss.Style
	destruct  lipgloss.Style
	identity  lipgloss.Style
	caution   lipgloss.Style
	unfocused lipgloss.Style
}

func newPalette(colors bool) palette {
	renderer := lipgloss.NewRenderer(io.Discard)
	if colors {
		renderer.SetColorProfile(termenv.ANSI256)
	} else {
		renderer.SetColorProfile(termenv.Ascii)
	}
	styles := palette{base: renderer.NewStyle(), muted: renderer.NewStyle(), healthy: renderer.NewStyle(), destruct: renderer.NewStyle(), identity: renderer.NewStyle(), caution: renderer.NewStyle(), unfocused: renderer.NewStyle()}
	if !colors {
		return styles
	}
	styles.base = styles.base.Foreground(lipgloss.Color("252"))
	styles.muted = styles.muted.Foreground(lipgloss.Color("242"))
	styles.healthy = styles.healthy.Foreground(lipgloss.Color("42"))
	styles.destruct = styles.destruct.Foreground(lipgloss.Color("205"))
	styles.identity = styles.identity.Foreground(lipgloss.Color("141"))
	styles.caution = styles.caution.Foreground(lipgloss.Color("214"))
	styles.unfocused = styles.unfocused.Foreground(lipgloss.Color("239"))
	return styles
}

func (model *Model) View() string {
	if model.closed {
		return ""
	}
	width := bounded(model.width, 1, maximumWidth)
	height := bounded(model.height, 1, maximumHeight)
	if width < narrowWidth || height < shortHeight {
		return fit(model.viewNarrow(width), width, height)
	}
	var view string
	if model.route == routeUpstream {
		view = model.viewUpstream(width, height)
	} else {
		view = model.viewDashboard(width, height)
	}
	return fit(view, width, height)
}

func (model *Model) viewDashboard(width, height int) string {
	styles := model.styles
	header := styles.identity.Bold(true).Render("WYRWOOD") + styles.muted.Render("  /  DIAGNOSTICS  /  DASHBOARD")
	upstreamHeight := 5
	footerHeight := model.footerHeight()
	bodyHeight := maximum(5, height-upstreamHeight-footerHeight-1)
	upstream := model.panel("UPSTREAM", model.dashboardUpstream(styles), width, upstreamHeight, model.focus == focusUpstream, styles)

	var body string
	if width < stackedWidth {
		if model.focus == focusSummary {
			body = model.panel("SELECTED CONSUMER", model.consumerSummary(styles), width, bodyHeight, true, styles)
		} else {
			body = model.panel("CONSUMERS", model.consumerRows(styles, bodyHeight-2), width, bodyHeight, model.focus == focusConsumers, styles)
		}
	} else {
		leftWidth := (width * 3) / 5
		rightWidth := width - leftWidth - 2
		left := model.panel("CONSUMERS", model.consumerRows(styles, bodyHeight-2), leftWidth, bodyHeight, model.focus == focusConsumers, styles)
		right := model.panel("SELECTED CONSUMER", model.consumerSummary(styles), rightWidth, bodyHeight, model.focus == focusSummary, styles)
		body = lipgloss.JoinHorizontal(lipgloss.Top, left, "  ", right)
	}
	return lipgloss.JoinVertical(lipgloss.Left, header, upstream, body, model.footer(styles))
}

func (model *Model) viewUpstream(width, height int) string {
	styles := model.styles
	header := styles.identity.Bold(true).Render("WYRWOOD") + styles.muted.Render("  /  DIAGNOSTICS  /  UPSTREAM")
	footerHeight := model.footerHeight()
	bodyHeight := maximum(5, height-footerHeight-2)
	connection := model.panel("UPSTREAM CONNECTION", model.upstreamConnection(styles), maximum(1, width), bodyHeight, true, styles)
	if width >= stackedWidth {
		leftWidth := (width * 2) / 5
		rightWidth := width - leftWidth - 2
		connection = lipgloss.JoinHorizontal(lipgloss.Top,
			model.panel("UPSTREAM CONNECTION", model.upstreamConnection(styles), leftWidth, bodyHeight, true, styles),
			"  ",
			model.panel("APPROVED EVENTS", model.upstreamEvents(styles, bodyHeight-2), rightWidth, bodyHeight, false, styles),
		)
	}
	return lipgloss.JoinVertical(lipgloss.Left, header, connection, model.footer(styles))
}

func (model *Model) viewNarrow(width int) string {
	styles := model.styles
	if model.route == routeUpstream {
		lines := []string{
			styles.identity.Bold(true).Render("UPSTREAM"),
			model.healthLabel(model.status.Upstream, model.statusState, styles),
			"socket " + model.upstreamSocket(),
			fmt.Sprintf("keys %s", model.countLabel(model.keysState, len(model.keys.Keys))),
			model.loadHint(model.eventsState),
			"esc Back  r Retry  ? Help",
			"q Quit",
		}
		return strings.Join(lines, "\n")
	}
	selected := "no configured consumer"
	if consumer, ok := model.selectedConsumer(); ok {
		selected = "> " + sanitize(consumer.Name)
		status, projected := model.statusFor(consumer.ID)
		if projected {
			selected += "  " + model.healthLabel(status.Listener, loadReady, styles)
		} else {
			selected += "  [--] STATUS NOT PROJECTED"
		}
	}
	lines := []string{
		styles.identity.Bold(true).Render("DASHBOARD"),
		"upstream " + model.healthLabel(model.status.Upstream, model.statusState, styles),
		"configuration " + model.configurationState.String(),
		selected,
		"tab Focus  enter Open  r Retry",
		"? Help  q Quit",
	}
	return strings.Join(lines, "\n")
}

func (model *Model) dashboardUpstream(styles palette) string {
	return strings.Join([]string{
		model.healthLabel(model.status.Upstream, model.statusState, styles) + "  " + model.upstreamSocket(),
		fmt.Sprintf("available keys %s  ·  configuration %s%s", model.countLabel(model.keysState, len(model.keys.Keys)), model.configurationState.String(), model.revisionLabel()),
	}, "\n")
}

func (model *Model) consumerRows(styles palette, availableHeight int) string {
	if model.configurationState != loadReady && model.configurationState != loadEmpty {
		return model.loadHint(model.configurationState)
	}
	if len(model.consumers) == 0 {
		return "EMPTY  No configured consumers."
	}
	rows := []string{"  NAME                 LISTENER                 CONNECTIONS"}
	selectedIndex := model.consumerList.Index()
	maximumRows := maximum(1, availableHeight-2)
	start := bounded(selectedIndex-maximumRows/2, 0, maximum(0, len(model.consumers)-maximumRows))
	end := minimum(len(model.consumers), start+maximumRows)
	for index := start; index < end; index++ {
		consumer := model.consumers[index]
		marker := " "
		if index == selectedIndex {
			marker = ">"
		}
		listener := "[--] STATUS NOT PROJECTED"
		connections := "--"
		if status, ok := model.statusFor(consumer.ID); ok {
			listener = model.healthLabel(status.Listener, loadReady, styles)
			connections = fmt.Sprintf("%d", status.ActiveConnections)
		}
		row := fmt.Sprintf("%s %-20s %-24s %s", marker, truncatePlain(sanitize(consumer.Name), 20), listener, connections)
		if index == selectedIndex {
			row = styles.identity.Bold(true).Render(row)
		}
		rows = append(rows, row)
	}
	if model.status.Truncated {
		rows = append(rows, styles.caution.Render("[!] STATUS INCOMPLETE — configured consumers remain authoritative"))
	}
	return strings.Join(rows, "\n")
}

func (model *Model) consumerSummary(styles palette) string {
	consumer, ok := model.selectedConsumer()
	if !ok {
		return model.loadHint(model.configurationState)
	}
	lines := []string{
		styles.identity.Bold(true).Render(sanitize(consumer.Name)),
		"socket " + sanitize(consumer.Socket),
		fmt.Sprintf("fingerprints %d", len(consumer.Fingerprints)),
	}
	for index, fingerprint := range consumer.Fingerprints {
		if index == 4 {
			lines = append(lines, fmt.Sprintf("  … %d more", len(consumer.Fingerprints)-index))
			break
		}
		lines = append(lines, styles.identity.Render("  • "+shortFingerprint(fingerprint)))
	}
	if status, projected := model.statusFor(consumer.ID); projected {
		lines = append(lines, model.healthLabel(status.Listener, loadReady, styles)+fmt.Sprintf("  ·  %d active connections", status.ActiveConnections))
	} else {
		lines = append(lines, "[--] STATUS NOT PROJECTED")
	}
	lines = append(lines, "", "RECENT APPROVED EVENTS")
	count := 0
	for index := len(model.events.Events) - 1; index >= 0 && count < 5; index-- {
		event := model.events.Events[index]
		if event.ConsumerID != consumer.ID {
			continue
		}
		lines = append(lines, renderEvent(event, styles))
		count++
	}
	if count == 0 {
		lines = append(lines, model.loadHint(model.eventsState))
	}
	return strings.Join(lines, "\n")
}

func (model *Model) upstreamConnection(styles palette) string {
	lines := []string{
		"status  " + model.healthLabel(model.status.Upstream, model.statusState, styles),
		"socket  " + model.upstreamSocket(),
		fmt.Sprintf("keys    %s", model.countLabel(model.keysState, len(model.keys.Keys))),
	}
	if model.keysState == loadReady {
		lines = append(lines, "", "AVAILABLE IDENTITIES")
		for index, key := range model.keys.Keys {
			if index == 6 {
				lines = append(lines, fmt.Sprintf("… %d more", len(model.keys.Keys)-index))
				break
			}
			label := sanitize(key.Display)
			if label == "" {
				label = "(no display label)"
			}
			lines = append(lines, styles.identity.Render("• "+shortFingerprint(key.Fingerprint))+"  "+label)
		}
	} else {
		lines = append(lines, "", model.loadHint(model.keysState))
	}
	return strings.Join(lines, "\n")
}

func (model *Model) upstreamEvents(styles palette, availableHeight int) string {
	if model.eventsState != loadReady && model.eventsState != loadEmpty {
		return model.loadHint(model.eventsState)
	}
	rows := make([]string, 0, minimum(availableHeight, len(model.events.Events)))
	for index := len(model.events.Events) - 1; index >= 0 && len(rows) < availableHeight; index-- {
		event := model.events.Events[index]
		if event.Operation == "upstream-connect" || event.Operation == "replay" {
			rows = append(rows, renderEvent(event, styles))
		}
	}
	if len(rows) == 0 {
		return "EMPTY  No retained upstream events."
	}
	return strings.Join(rows, "\n")
}

func renderEvent(event Event, styles palette) string {
	marker := "[OK]"
	style := styles.healthy
	if event.Outcome == "denied" || event.Outcome == "failed" {
		marker = "[!]"
		style = styles.caution
	}
	return fmt.Sprintf("%s %s %-16s %s", event.Timestamp.UTC().Format("15:04:05"), style.Render(marker), sanitize(event.Operation), sanitize(event.Outcome))
}

func (model *Model) panel(title, body string, width, height int, focused bool, styles palette) string {
	border := lipgloss.NormalBorder()
	borderStyle := styles.unfocused
	focusLabel := ""
	if focused {
		border = lipgloss.DoubleBorder()
		borderStyle = styles.identity
		focusLabel = " [FOCUS]"
	}
	contentWidth := maximum(1, width-4)
	contentHeight := maximum(1, height-2)
	content := styles.identity.Bold(true).Render(title) + focusLabel + "\n" + fit(body, contentWidth, maximum(1, contentHeight-1))
	return styles.base.
		Width(contentWidth).
		Height(contentHeight).
		Padding(0, 1).
		Border(border).
		BorderForeground(borderStyle.GetForeground()).
		Render(content)
}

func (model *Model) footer(styles palette) string {
	var lines []string
	if model.route == routeUpstream {
		lines = []string{"esc Back   r Refresh   ? Help   q Quit"}
	} else {
		lines = []string{"tab/shift+tab Focus   ↑/↓ Select   enter Open   r Refresh   ? Help   q Quit"}
	}
	if model.help {
		lines = append(lines, "All actions are keyboard-only. Refresh retries unavailable panels; color is never the sole state signal.")
	}
	return styles.muted.Render(strings.Join(lines, "\n"))
}

func (model *Model) footerHeight() int {
	if model.help {
		return 2
	}
	return 1
}

func (model *Model) upstreamSocket() string {
	if model.configurationState != loadReady && model.configurationState != loadEmpty {
		return "[--] " + model.configurationState.String()
	}
	if model.configuration.Upstream == "" {
		return "[--] NOT CONFIGURED"
	}
	return sanitize(model.configuration.Upstream)
}

func (model *Model) healthLabel(value Health, state loadState, styles palette) string {
	if state != loadReady && state != loadEmpty {
		return "[--] " + state.String()
	}
	switch value {
	case HealthHealthy:
		return styles.healthy.Render("[OK] HEALTHY")
	case HealthDegraded:
		return styles.caution.Render("[!] DEGRADED")
	default:
		return styles.destruct.Render("[X] UNAVAILABLE")
	}
}

func (model *Model) loadHint(state loadState) string {
	if state == loadEmpty {
		return "EMPTY  No retained data."
	}
	if state == loadReady {
		return "READY"
	}
	return state.String() + "  ·  r RETRY"
}

func (model *Model) countLabel(state loadState, count int) string {
	if state == loadReady || state == loadEmpty {
		return fmt.Sprintf("%d", count)
	}
	return state.String()
}

func (model *Model) revisionLabel() string {
	if model.configuration.Revision == "" || model.status.ActiveRevision == "" {
		return ""
	}
	if model.configuration.Revision != model.status.ActiveRevision {
		return "  ·  [!] UNAPPLIED"
	}
	return "  ·  [OK] ACTIVE"
}

func (model *Model) statusFor(id string) (ConsumerStatus, bool) {
	for _, status := range model.status.Consumers {
		if status.ID == id {
			return status, true
		}
	}
	return ConsumerStatus{}, false
}

func shortFingerprint(value string) string {
	value = sanitize(value)
	if utf8.RuneCountInString(value) <= 22 {
		return value
	}
	runes := []rune(value)
	return string(runes[:19]) + "…"
}

func sanitize(value string) string {
	var builder strings.Builder
	for _, current := range value {
		if unicode.IsControl(current) || unicode.In(current, unicode.Cf) {
			builder.WriteRune('�')
		} else {
			builder.WriteRune(current)
		}
		if builder.Len() >= 512 {
			break
		}
	}
	return builder.String()
}

func truncatePlain(value string, width int) string {
	return ansi.Truncate(value, maximum(0, width), "…")
}

func fit(value string, width, height int) string {
	if width < 1 || height < 1 {
		return ""
	}
	lines := strings.Split(value, "\n")
	if len(lines) > height {
		lines = lines[:height]
	}
	for index := range lines {
		lines[index] = ansi.Truncate(lines[index], width, "")
	}
	return strings.Join(lines, "\n")
}
