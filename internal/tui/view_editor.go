//go:build linux

// ---
// relationships:
//   implements: terminal-interface
// ---

package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (model *Model) viewEditor(width, height int) string {
	styles := model.styles
	editor := model.editor
	title := "UPSTREAM ENDPOINT"
	if editor.kind == editTimeouts {
		title = "SETTINGS / TIMEOUTS"
	} else if editor.kind == editConsumer {
		if editor.consumerID == nil {
			title = "NEW CONSUMER"
		} else {
			title = "EDIT CONSUMER"
		}
	}
	header := styles.identity.Bold(true).Render("WYRWOOD") + styles.muted.Render("  /  CONFIGURATION  /  "+title)
	state := editorStateLabel(editor)
	if width < narrowWidth || height < shortHeight {
		focused := editor.focusedSummary()
		lines := []string{styles.identity.Bold(true).Render(title), state, focused, "tab Next  shift+tab Previous", "enter Activate  esc Cancel"}
		if editor.conflict {
			lines = append(lines, "R Reload  esc Cancel")
		}
		if model.notice != "" {
			lines = append(lines, model.notice)
		}
		view := strings.Join(lines, "\n")
		if model.modal != modalNone {
			view = overlayBottom(view, model.viewModal(width), width, height)
		}
		return view
	}
	bodyHeight := maximum(8, height-5)
	body := model.editorBody(editor, styles, bodyHeight-2)
	footer := "tab/shift+tab Traverse   enter Activate   esc Cancel"
	if editor.kind == editConsumer {
		footer += "   ↑/↓ Keys   space Toggle"
	}
	if editor.conflict {
		footer += "   R Reload"
	}
	if model.notice != "" {
		footer += "\n" + model.notice
	}
	view := lipgloss.JoinVertical(lipgloss.Left, header, model.panel(title+" · "+state, body, width, bodyHeight, true, styles), styles.muted.Render(footer))
	if model.modal != modalNone {
		view = overlayBottom(view, model.viewModal(width), width, height)
	}
	return view
}

func editorStateLabel(editor *editorState) string {
	labels := make([]string, 0, 3)
	if editor.dirty {
		labels = append(labels, "DIRTY")
	} else {
		labels = append(labels, "CLEAN")
	}
	if editor.conflict {
		labels = append(labels, "CONFLICT · Save disabled · R Reload or esc Cancel")
	}
	if editor.saving {
		labels = append(labels, "SAVING")
	}
	if editor.reloading {
		labels = append(labels, "RELOADING · input disabled")
	}
	if editor.failure != "" && !editor.conflict {
		labels = append(labels, editor.failure)
	}
	return strings.Join(labels, " · ")
}

func (editor *editorState) focusedSummary() string {
	if editor.focus < len(editor.inputs) {
		label, errorKey := editor.inputLabel(editor.focus)
		value := sanitize(editor.inputs[editor.focus].Value())
		if value == "" {
			value = "(empty)"
		}
		result := "> " + label + ": " + value
		if problem := editor.errors[errorKey]; problem != "" {
			result += " · INVALID — " + problem
		}
		return result
	}
	if editor.focus == editor.fingerprintFocus() && len(editor.fingerprints) > 0 {
		choice := editor.fingerprints[editor.fingerprintIndex]
		checked := "[ ]"
		if choice.Selected {
			checked = "[x]"
		}
		return "> " + checked + " " + shortFingerprint(choice.Fingerprint)
	}
	if editor.focus == editor.browseFocus() {
		return "> [BROWSE] ADVISORY ONLY"
	}
	if editor.focus == editor.saveFocus() {
		return "> [SAVE]"
	}
	return "> [CANCEL]"
}

func (editor *editorState) inputLabel(index int) (string, string) {
	switch editor.kind {
	case editUpstream:
		return "Socket path", "upstream"
	case editTimeouts:
		return []string{"Connect (100ms–30s)", "List (100ms–30s)", "Replay (100ms–30s)", "Sign (1s–10m)"}[index], timeoutName(index)
	default:
		return []string{"Name", "Socket path", "Access group (optional numeric)"}[index], []string{"name", "socket", "access-group"}[index]
	}
}

func (model *Model) editorBody(editor *editorState, styles palette, availableHeight int) string {
	var lines []string
	switch editor.kind {
	case editUpstream:
		lines = append(lines, model.formField(editor, 0, "Socket path", "upstream", styles))
		lines = append(lines, model.action(editor, editor.browseFocus(), "BROWSE SOCKETS", true, styles)+"  ADVISORY ONLY — existence does not authorize or prove reachability")
	case editTimeouts:
		labels := []string{"Connect (100ms–30s)", "List (100ms–30s)", "Replay (100ms–30s)", "Sign (1s–10m)"}
		for index, label := range labels {
			lines = append(lines, model.formField(editor, index, label, timeoutName(index), styles))
		}
	case editConsumer:
		lines = append(lines,
			model.formField(editor, 0, "Name", "name", styles),
			model.formField(editor, 1, "Socket path", "socket", styles),
			"  Dedicated parent required; missing ancestors are not created.",
			model.formField(editor, 2, "Access group (optional numeric)", "access-group", styles),
		)
		if editor.consumerID != nil && editor.inputs[1].Value() != editor.originalConsumer.Socket {
			lines = append(lines, styles.caution.Render("[!] NEW SECURITY PRINCIPAL — apply replaces the endpoint and closes its connections"))
		}
		lines = append(lines, "", "EXPOSED FINGERPRINTS")
		if len(editor.fingerprints) == 0 {
			lines = append(lines, "[ ] EMPTY  No upstream identities offered.")
		}
		start := bounded(editor.fingerprintIndex-3, 0, maximum(0, len(editor.fingerprints)-7))
		end := minimum(len(editor.fingerprints), start+7)
		for index := start; index < end; index++ {
			choice := editor.fingerprints[index]
			marker := "  "
			if editor.focus == editor.fingerprintFocus() && editor.fingerprintIndex == index {
				marker = ">>"
			}
			checked := "[ ]"
			if choice.Selected {
				checked = "[x]"
			}
			label := marker + " " + checked + " " + shortFingerprint(choice.Fingerprint)
			if choice.Offered {
				if choice.Display != "" {
					label += "  " + sanitize(choice.Display)
				}
			} else {
				label += "  UNAVAILABLE"
			}
			lines = append(lines, styles.identity.Render(label))
		}
	}
	if problem := editor.errors["form"]; problem != "" {
		lines = append(lines, styles.caution.Render("INVALID  "+problem))
	}
	validSave := editor.canSaveWithoutValidation()
	lines = append(lines, "", model.action(editor, editor.saveFocus(), saveLabel(editor), validSave, styles)+"   "+model.action(editor, editor.cancelFocus(), "CANCEL", true, styles))
	return fit(strings.Join(lines, "\n"), maximum(1, model.width-4), availableHeight)
}

func saveLabel(editor *editorState) string {
	if editor.kind == editConsumer && editor.consumerID == nil {
		return "CREATE"
	}
	return "SAVE"
}

func (editor *editorState) canSaveWithoutValidation() bool {
	return editor.dirty && !editor.conflict && !editor.saving && len(editor.errors) == 0
}

func (model *Model) formField(editor *editorState, index int, label, key string, styles palette) string {
	marker := "  "
	if editor.focus == index {
		marker = ">>"
	}
	value := editor.inputs[index].View()
	line := fmt.Sprintf("%s %s  %s", marker, label, value)
	if problem := editor.errors[key]; problem != "" {
		line += "\n" + styles.caution.Render("   INVALID — "+problem)
	}
	return line
}

func (model *Model) action(editor *editorState, focus int, label string, enabled bool, styles palette) string {
	marker := "  "
	if editor.focus == focus {
		marker = ">>"
	}
	if !enabled {
		return marker + " [" + label + " DISABLED — fix invalid fields, change a value, or reload conflict]"
	}
	return styles.destruct.Render(marker + " [" + label + "]")
}

func (model *Model) viewBrowser(width, height int) string {
	styles := model.styles
	lines := []string{
		styles.identity.Bold(true).Render("BROWSE UPSTREAM SOCKETS"),
		"ADVISORY ONLY — selection grants no authority and proves no agent reachability.",
		"directory " + sanitize(model.browserState.parent), "",
	}
	if model.browserState.loading {
		lines = append(lines, "LOADING")
	} else if model.browserState.state != loadReady {
		lines = append(lines, model.browserState.state.String())
		if model.browserState.truncated {
			lines = append(lines, "[!] BROWSE INCOMPLETE — manual entry remains available")
		}
	} else {
		maximumRows := maximum(1, height-8)
		start := bounded(model.browserState.index-maximumRows/2, 0, maximum(0, len(model.browserState.entries)-maximumRows))
		end := minimum(len(model.browserState.entries), start+maximumRows)
		for index := start; index < end; index++ {
			entry := model.browserState.entries[index]
			marker := "  "
			kind := "SOCKET"
			if entry.Directory {
				kind = "DIR"
			}
			if index == model.browserState.index {
				marker = ">>"
			}
			lines = append(lines, fmt.Sprintf("%s [%s] %s", marker, kind, sanitize(entry.Path)))
		}
		if model.browserState.truncated {
			lines = append(lines, "[!] BROWSE INCOMPLETE — manual entry remains available")
		}
	}
	lines = append(lines, "", "↑/↓ Select   enter Open/choose   esc Manual entry")
	return fit(strings.Join(lines, "\n"), width, height)
}

func (model *Model) viewModal(width int) string {
	switch model.modal {
	case modalDiscard:
		return fit("[CONFIRM] Discard local edits?\nd Discard   k Keep editing", width, 2)
	case modalExit:
		return fit("[CONFIRM] Discard local edits and exit?\nd Discard and exit   k Keep editing   ctrl+c Force exit", width, 2)
	case modalRetire:
		name := "selected consumer"
		if consumer, ok := model.selectedConsumer(); ok {
			name = sanitize(consumer.Name)
		}
		return fit("[DESTRUCTIVE] Retire "+name+"?\nApply closes connections and removes only the owned socket. y Confirm   esc Cancel", width, 2)
	default:
		return ""
	}
}
