//go:build linux

// ---
// relationships:
//   implements: terminal-interface
//   uses: control-interface
// ---

package tui

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/wyrd-company/wyrwood/internal/config"
)

func (editor *editorState) candidateConfig(model *Model) (config.Config, error) {
	candidate, err := model.configCandidate()
	if err != nil {
		return config.Config{}, err
	}
	switch editor.kind {
	case editUpstream:
		candidate.Upstream = editor.inputs[0].Value()
	case editTimeouts:
		values := make([]time.Duration, len(editor.inputs))
		for index, field := range editor.inputs {
			value, parseErr := time.ParseDuration(field.Value())
			if parseErr != nil {
				return config.Config{}, parseErr
			}
			values[index] = value
		}
		if len(values) != 4 {
			return config.Config{}, errors.New("timeout candidate is incomplete")
		}
		candidate.Timeouts = config.Timeouts{Connect: values[0], List: values[1], Replay: values[2], Sign: values[3]}
	case editConsumer:
		consumer, candidateErr := editor.consumerCandidate()
		if candidateErr != nil {
			return config.Config{}, candidateErr
		}
		projected := config.Consumer{Name: consumer.Name, Socket: consumer.Socket, AccessGroup: consumer.AccessGroup, Fingerprints: consumer.Fingerprints}
		if editor.consumerID == nil {
			candidate.Consumers = append(candidate.Consumers, projected)
		} else {
			found := false
			for index, current := range model.consumers {
				if current.ID == *editor.consumerID {
					candidate.Consumers[index] = projected
					found = true
					break
				}
			}
			if !found {
				return config.Config{}, errors.New("consumer is no longer configured")
			}
		}
	}
	return candidate, config.Validate(candidate)
}

func (editor *editorState) candidateRevision(model *Model) (string, error) {
	candidate, err := editor.candidateConfig(model)
	if err != nil {
		return "", err
	}
	data, err := config.MarshalCanonical(candidate)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest), nil
}

func (model *Model) startDurabilityVerification() tea.Cmd {
	editor := model.editor
	if editor == nil {
		return model.startRefresh(true, true)
	}
	revision, err := editor.candidateRevision(model)
	if err != nil {
		editor.conflict = true
		editor.failure = "SAVE COMMIT UNCERTAIN · candidate cannot be verified · R Reload"
		model.setNotice(editor.failure, true)
		return nil
	}
	editor.verifying = true
	editor.verificationRevision = revision
	editor.reloadConfiguration = ConfigurationPage{}
	editor.reloadConsumers = nil
	return model.startRefresh(true, true)
}

func (model *Model) updateVerificationConfiguration(message configurationMsg) (tea.Model, tea.Cmd) {
	editor := model.editor
	if editor == nil || !editor.verifying {
		return model, model.settleRefreshOperation(refreshConfiguration)
	}
	if message.err != nil {
		editor.verifying = false
		editor.conflict = true
		editor.failure = "SAVE COMMIT UNCERTAIN · verification unavailable · R Reload"
		model.setNotice(editor.failure, true)
		return model, model.settleRefreshOperation(refreshConfiguration)
	}
	if message.offset == 0 {
		editor.reloadConfiguration = message.page
		editor.reloadConsumers = append([]Consumer(nil), message.page.Consumers...)
	} else {
		if message.page.Revision != editor.reloadConfiguration.Revision {
			return model.failDurabilityVerification("configuration revision changed during verification")
		}
		editor.reloadConsumers = append(editor.reloadConsumers, message.page.Consumers...)
	}
	if len(editor.reloadConsumers) > message.page.TotalConsumers {
		return model.failDurabilityVerification("incoherent configuration projection")
	}
	if message.page.NextOffset != nil {
		return model, model.loadConfiguration(message.generation, *message.page.NextOffset, message.page.Revision)
	}
	if len(editor.reloadConsumers) != message.page.TotalConsumers {
		return model.failDurabilityVerification("incomplete configuration projection")
	}

	fetchedRevision := editor.reloadConfiguration.Revision
	switch fetchedRevision {
	case editor.baseRevision:
		editor.verifying = false
		editor.failure = "SAVE VERIFIED NOT COMMITTED · candidate preserved"
		model.setNotice(editor.failure, false)
		return model, model.settleRefreshOperation(refreshConfiguration)
	case editor.verificationRevision:
		model.configuration = editor.reloadConfiguration
		model.consumers = append([]Consumer(nil), editor.reloadConsumers...)
		model.configurationState = stateFor(nil, len(model.consumers))
		model.setConsumerItems()
		model.closeEditor()
		model.setNotice("SAVE VERIFIED PUBLISHED · UNAPPLIED", false)
		return model, model.settleRefreshOperation(refreshConfiguration)
	default:
		return model.failDurabilityVerification("external configuration change")
	}
}

func (model *Model) failDurabilityVerification(reason string) (tea.Model, tea.Cmd) {
	if model.editor != nil {
		model.editor.verifying = false
		model.editor.conflict = true
		model.editor.failure = "SAVE COMMIT UNCERTAIN · CONFLICT · " + reason + " · R Reload"
		model.setNotice(model.editor.failure, true)
	}
	return model, model.settleRefreshOperation(refreshConfiguration)
}

func (model *Model) setNotice(value string, sticky bool) {
	model.notice = value
	model.noticeSticky = sticky
}

func (model *Model) clearTransientNotice() {
	if model.notice == "" || model.noticeSticky {
		return
	}
	previous := model.notice
	model.notice = ""
	model.noticeSticky = false
	if model.editor != nil && model.editor.failure == previous {
		model.editor.failure = ""
	}
}
