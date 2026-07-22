//go:build linux

// ---
// relationships:
//   uses: control-interface
//   implements: terminal-interface
// ---

// Package tui implements Wyrwood's keyboard-operated terminal client.
package tui

import (
	"context"
	"errors"
	"time"

	"github.com/wyrd-company/wyrwood/internal/control"
)

const (
	configurationPageSize = 16
	eventLimit            = 100
	refreshInterval       = 5 * time.Second
)

// ErrConfigurationUnavailable marks the temporary integration seam that task
// 32 replaces with the daemon's paginated configuration operation. It is kept
// categorical so the application never falls back to reading YAML directly.
var ErrConfigurationUnavailable = errors.New("configuration projection unavailable")

// ErrDenied is a categorical client failure used by tests and future transport
// adapters. It contains no displayable low-level error text.
var ErrDenied = errors.New("control request denied")

// Client is the presentation-independent, context-aware read boundary used by
// the terminal state machine. Implementations must return promptly after the
// supplied context is canceled.
type Client interface {
	Configuration(context.Context, int, int, string) (ConfigurationPage, error)
	Keys(context.Context) (Keys, error)
	Status(context.Context) (Status, error)
	Events(context.Context, int) (Events, error)
}

// ConfigurationPage is one coherent page of the approved editable model.
type ConfigurationPage struct {
	Revision       string
	Upstream       string
	Timeouts       Timeouts
	TotalConsumers int
	Consumers      []Consumer
	NextOffset     *int
}

type Timeouts struct {
	Connect string
	List    string
	Replay  string
	Sign    string
}

type Consumer struct {
	ID           string
	Name         string
	Socket       string
	AccessGroup  *uint32
	Fingerprints []string
}

type Key struct {
	Fingerprint string
	Display     string
}

type Keys struct{ Keys []Key }

type Health string

const (
	HealthHealthy     Health = "healthy"
	HealthDegraded    Health = "degraded"
	HealthUnavailable Health = "unavailable"
)

type ConsumerStatus struct {
	ID                string
	Name              string
	Listener          Health
	ActiveConnections int
}

type Status struct {
	ActiveRevision string
	Daemon         Health
	Upstream       Health
	Consumers      []ConsumerStatus
	Truncated      bool
}

type Event struct {
	Timestamp   time.Time
	ConsumerID  string
	Operation   string
	Fingerprint *string
	Outcome     string
	ErrorCode   string
}

type Events struct{ Events []Event }

type contextControlClient interface {
	KeysContext(context.Context) (control.KeysResult, error)
	StatusContext(context.Context) (control.StatusResult, error)
	EventsContext(context.Context, int) (control.EventsResult, error)
}

// ControlClient adapts the existing local control client without exposing
// transport or daemon implementation details to the application model.
type ControlClient struct{ client contextControlClient }

func NewControlClient(client contextControlClient) *ControlClient {
	return &ControlClient{client: client}
}

func (*ControlClient) Configuration(context.Context, int, int, string) (ConfigurationPage, error) {
	return ConfigurationPage{}, ErrConfigurationUnavailable
}

func (client *ControlClient) Keys(ctx context.Context) (Keys, error) {
	result, err := client.client.KeysContext(ctx)
	if err != nil {
		return Keys{}, err
	}
	keys := make([]Key, len(result.Keys))
	for index, key := range result.Keys {
		keys[index] = Key{Fingerprint: key.Fingerprint, Display: key.Display}
	}
	return Keys{Keys: keys}, nil
}

func (client *ControlClient) Status(ctx context.Context) (Status, error) {
	result, err := client.client.StatusContext(ctx)
	if err != nil {
		return Status{}, err
	}
	consumers := make([]ConsumerStatus, len(result.Consumers))
	for index, consumer := range result.Consumers {
		consumers[index] = ConsumerStatus{
			ID:                consumer.ID,
			Name:              consumer.Name,
			Listener:          health(consumer.Listener),
			ActiveConnections: consumer.ActiveConnections,
		}
	}
	return Status{
		Daemon:    health(result.Daemon),
		Upstream:  health(result.Upstream),
		Consumers: consumers,
		Truncated: result.Truncated,
	}, nil
}

func (client *ControlClient) Events(ctx context.Context, limit int) (Events, error) {
	result, err := client.client.EventsContext(ctx, limit)
	if err != nil {
		return Events{}, err
	}
	events := make([]Event, len(result.Events))
	for index, event := range result.Events {
		events[index] = Event{
			Timestamp:   event.Timestamp,
			ConsumerID:  event.ConsumerID,
			Operation:   event.Operation,
			Fingerprint: event.Fingerprint,
			Outcome:     event.Outcome,
			ErrorCode:   event.ErrorCode,
		}
	}
	return Events{Events: events}, nil
}

func health(value control.HealthCategory) Health {
	switch value {
	case control.HealthHealthy:
		return HealthHealthy
	case control.HealthDegraded:
		return HealthDegraded
	default:
		return HealthUnavailable
	}
}
