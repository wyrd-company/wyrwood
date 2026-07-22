//go:build linux

// ---
// relationships:
//   implements: control-interface
//   uses: configuration
// ---

package daemon

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/control"
)

func (service *Service) Configuration(offset, limit int, expectedRevision *string) (control.ConfigurationResult, control.ErrorCode) {
	loaded, err := loadConfigurationDocument(service.configPath, service.uid, nil)
	if err != nil {
		return control.ConfigurationResult{}, configurationErrorCode(err)
	}
	if expectedRevision != nil && *expectedRevision != loaded.revision {
		return control.ConfigurationResult{}, control.ErrorConfigurationConflict
	}
	consumers := slices.Clone(loaded.value.Consumers)
	slices.SortFunc(consumers, func(left, right config.Consumer) int { return strings.Compare(left.Socket, right.Socket) })
	if offset > len(consumers) {
		return control.ConfigurationResult{}, control.ErrorConfigurationNotFound
	}
	end := min(offset+limit, len(consumers))
	projected := make([]control.ConfigurationConsumer, 0, end-offset)
	for _, consumer := range consumers[offset:end] {
		projected = append(projected, projectConsumer(consumer))
	}
	return control.ConfigurationResult{
		Revision: loaded.revision, Upstream: loaded.value.Upstream, Timeouts: projectTimeouts(loaded.value.Timeouts),
		TotalConsumers: len(consumers), Offset: offset, Consumers: projected, Complete: end == len(consumers),
	}, control.ErrorNone
}

func (service *Service) SetUpstream(expectedRevision, upstream string) (control.ConfigurationChangeResult, control.ErrorCode) {
	return service.mutateConfiguration(control.OperationSetUpstream, expectedRevision, func(configuration *config.Config) (*string, error) {
		configuration.Upstream = upstream
		return nil, nil
	})
}

func (service *Service) SetTimeouts(expectedRevision string, timeouts control.ConfigurationTimeouts) (control.ConfigurationChangeResult, control.ErrorCode) {
	parsed, err := parseTimeouts(timeouts)
	if err != nil {
		return control.ConfigurationChangeResult{}, control.ErrorConfigurationInvalid
	}
	return service.mutateConfiguration(control.OperationSetTimeouts, expectedRevision, func(configuration *config.Config) (*string, error) {
		configuration.Timeouts = parsed
		return nil, nil
	})
}

func (service *Service) PutConsumer(expectedRevision string, existingID *string, candidate control.ConfigurationConsumerInput) (control.ConfigurationChangeResult, control.ErrorCode) {
	return service.mutateConfiguration(control.OperationPutConsumer, expectedRevision, func(configuration *config.Config) (*string, error) {
		next := config.Consumer{
			Name: candidate.Name, Socket: candidate.Socket, AccessGroup: candidate.AccessGroup,
			Fingerprints: slices.Clone(candidate.Fingerprints),
		}
		if existingID == nil {
			configuration.Consumers = append(configuration.Consumers, next)
		} else {
			index := consumerIndex(configuration.Consumers, *existingID)
			if index < 0 {
				return nil, errConfigurationNotFound
			}
			configuration.Consumers[index] = next
		}
		identifier := consumerIdentifier(candidate.Socket)
		return &identifier, nil
	})
}

func (service *Service) RetireConsumer(expectedRevision, consumerID string) (control.ConfigurationChangeResult, control.ErrorCode) {
	return service.mutateConfiguration(control.OperationRetireConsumer, expectedRevision, func(configuration *config.Config) (*string, error) {
		index := consumerIndex(configuration.Consumers, consumerID)
		if index < 0 {
			return nil, errConfigurationNotFound
		}
		configuration.Consumers = slices.Delete(configuration.Consumers, index, index+1)
		return &consumerID, nil
	})
}

func (service *Service) mutateConfiguration(operation control.Operation, expectedRevision string, change func(*config.Config) (*string, error)) (control.ConfigurationChangeResult, control.ErrorCode) {
	service.configurationMu.Lock()
	defer service.configurationMu.Unlock()
	directory, err := openConfigurationDirectory(service.configPath, service.uid)
	if err != nil {
		return control.ConfigurationChangeResult{}, configurationErrorCode(err)
	}
	defer directory.close()
	loaded, err := directory.read(nil)
	if err != nil {
		return control.ConfigurationChangeResult{}, configurationErrorCode(err)
	}
	if loaded.revision != expectedRevision {
		return control.ConfigurationChangeResult{}, control.ErrorConfigurationConflict
	}
	consumerID, err := change(&loaded.value)
	if err != nil {
		return control.ConfigurationChangeResult{}, configurationErrorCode(err)
	}
	data, err := config.MarshalCanonical(loaded.value)
	if err != nil || len(data) > config.MaximumDocumentBytes {
		return control.ConfigurationChangeResult{}, control.ErrorConfigurationInvalid
	}
	published, err := directory.replace(loaded.revision, data, service.publication)
	newRevision := configurationRevision(data)
	if err != nil {
		if published {
			return control.ConfigurationChangeResult{}, control.ErrorConfigurationDurabilityUncertain
		}
		return control.ConfigurationChangeResult{}, configurationErrorCode(err)
	}
	return control.ConfigurationChangeResult{
		Operation: operation, Revision: newRevision, Changed: published, ConsumerID: consumerID,
	}, control.ErrorNone
}

func configurationErrorCode(err error) control.ErrorCode {
	var invalid *invalidConfigurationError
	switch {
	case errors.Is(err, errConfigurationConflict):
		return control.ErrorConfigurationConflict
	case errors.Is(err, errConfigurationNotFound):
		return control.ErrorConfigurationNotFound
	case errors.As(err, &invalid):
		return control.ErrorConfigurationInvalid
	default:
		return control.ErrorConfigurationFailed
	}
}

func parseTimeouts(value control.ConfigurationTimeouts) (config.Timeouts, error) {
	values := []*time.Duration{new(time.Duration), new(time.Duration), new(time.Duration), new(time.Duration)}
	for index, text := range []string{value.Connect, value.List, value.Replay, value.Sign} {
		parsed, err := time.ParseDuration(text)
		if err != nil {
			return config.Timeouts{}, err
		}
		*values[index] = parsed
	}
	return config.Timeouts{Connect: *values[0], List: *values[1], Replay: *values[2], Sign: *values[3]}, nil
}

func projectTimeouts(value config.Timeouts) control.ConfigurationTimeouts {
	return control.ConfigurationTimeouts{Connect: value.Connect.String(), List: value.List.String(), Replay: value.Replay.String(), Sign: value.Sign.String()}
}

func projectConsumer(value config.Consumer) control.ConfigurationConsumer {
	return control.ConfigurationConsumer{
		ID: consumerIdentifier(value.Socket),
		ConfigurationConsumerInput: control.ConfigurationConsumerInput{
			Name: value.Name, Socket: value.Socket, AccessGroup: value.AccessGroup, Fingerprints: slices.Clone(value.Fingerprints),
		},
	}
}

func consumerIndex(consumers []config.Consumer, identifier string) int {
	return slices.IndexFunc(consumers, func(consumer config.Consumer) bool { return consumerIdentifier(consumer.Socket) == identifier })
}
