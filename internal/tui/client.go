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
	"time"

	"github.com/wyrd-company/wyrwood/internal/control"
)

const (
	configurationPageSize = 16
	eventLimit            = 100
	refreshInterval       = 5 * time.Second
)

// Client is the presentation-independent, context-aware read boundary used by
// the terminal state machine. Implementations must return promptly after the
// supplied context is canceled.
type Client interface {
	Configuration(context.Context, int, int, string) (ConfigurationPage, error)
	Keys(context.Context) (Keys, error)
	Status(context.Context) (Status, error)
	Events(context.Context, int) (Events, error)
	Apply(context.Context) (ApplyResult, error)
	SetUpstream(context.Context, string, string) (ConfigurationChange, error)
	SetTimeouts(context.Context, string, Timeouts) (ConfigurationChange, error)
	PutConsumer(context.Context, string, *string, Consumer) (ConfigurationChange, error)
	RetireConsumer(context.Context, string, string) (ConfigurationChange, error)
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

type ApplyResult struct {
	Revision           string
	Committed          bool
	Degraded           bool
	PendingCleanup     int
	PendingPermissions int
}

type ConfigurationChange struct {
	Revision   string
	Changed    bool
	ConsumerID *string
}

type contextControlClient interface {
	ConfigurationContext(context.Context, int, int, string) (control.ConfigurationResult, error)
	KeysContext(context.Context) (control.KeysResult, error)
	StatusContext(context.Context) (control.StatusResult, error)
	EventsContext(context.Context, int) (control.EventsResult, error)
	ApplyContext(context.Context) (control.ApplyResult, error)
	SetUpstreamContext(context.Context, string, string) (control.ConfigurationChangeResult, error)
	SetTimeoutsContext(context.Context, string, control.ConfigurationTimeouts) (control.ConfigurationChangeResult, error)
	PutConsumerContext(context.Context, string, *string, control.ConfigurationConsumerInput) (control.ConfigurationChangeResult, error)
	RetireConsumerContext(context.Context, string, string) (control.ConfigurationChangeResult, error)
}

// ControlClient adapts the existing local control client without exposing
// transport or daemon implementation details to the application model.
type ControlClient struct{ client contextControlClient }

func NewControlClient(client contextControlClient) *ControlClient {
	return &ControlClient{client: client}
}

func (client *ControlClient) Configuration(ctx context.Context, offset, limit int, revision string) (ConfigurationPage, error) {
	result, err := client.client.ConfigurationContext(ctx, offset, limit, revision)
	if err != nil {
		return ConfigurationPage{}, err
	}
	consumers := make([]Consumer, len(result.Consumers))
	for index, consumer := range result.Consumers {
		consumers[index] = Consumer{
			ID:           consumer.ID,
			Name:         consumer.Name,
			Socket:       consumer.Socket,
			AccessGroup:  consumer.AccessGroup,
			Fingerprints: append([]string(nil), consumer.Fingerprints...),
		}
	}
	var nextOffset *int
	if !result.Complete {
		next := result.Offset + len(result.Consumers)
		nextOffset = &next
	}
	return ConfigurationPage{
		Revision: result.Revision,
		Upstream: result.Upstream,
		Timeouts: Timeouts{
			Connect: result.Timeouts.Connect,
			List:    result.Timeouts.List,
			Replay:  result.Timeouts.Replay,
			Sign:    result.Timeouts.Sign,
		},
		TotalConsumers: result.TotalConsumers,
		Consumers:      consumers,
		NextOffset:     nextOffset,
	}, nil
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
		ActiveRevision: result.ActiveRevision,
		Daemon:         health(result.Daemon),
		Upstream:       health(result.Upstream),
		Consumers:      consumers,
		Truncated:      result.Truncated,
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

func (client *ControlClient) Apply(ctx context.Context) (ApplyResult, error) {
	result, err := client.client.ApplyContext(ctx)
	if err != nil {
		return ApplyResult{}, err
	}
	return ApplyResult{
		Revision: result.Revision, Committed: result.Committed, Degraded: result.Degraded,
		PendingCleanup: result.PendingCleanup, PendingPermissions: result.PendingPermissions,
	}, nil
}

func (client *ControlClient) SetUpstream(ctx context.Context, revision, upstream string) (ConfigurationChange, error) {
	result, err := client.client.SetUpstreamContext(ctx, revision, upstream)
	return configurationChange(result), err
}

func (client *ControlClient) SetTimeouts(ctx context.Context, revision string, timeouts Timeouts) (ConfigurationChange, error) {
	result, err := client.client.SetTimeoutsContext(ctx, revision, control.ConfigurationTimeouts{
		Connect: timeouts.Connect, List: timeouts.List, Replay: timeouts.Replay, Sign: timeouts.Sign,
	})
	return configurationChange(result), err
}

func (client *ControlClient) PutConsumer(ctx context.Context, revision string, consumerID *string, consumer Consumer) (ConfigurationChange, error) {
	result, err := client.client.PutConsumerContext(ctx, revision, consumerID, control.ConfigurationConsumerInput{
		Name: consumer.Name, Socket: consumer.Socket, AccessGroup: consumer.AccessGroup,
		Fingerprints: append([]string(nil), consumer.Fingerprints...),
	})
	return configurationChange(result), err
}

func (client *ControlClient) RetireConsumer(ctx context.Context, revision, consumerID string) (ConfigurationChange, error) {
	result, err := client.client.RetireConsumerContext(ctx, revision, consumerID)
	return configurationChange(result), err
}

func configurationChange(result control.ConfigurationChangeResult) ConfigurationChange {
	return ConfigurationChange{Revision: result.Revision, Changed: result.Changed, ConsumerID: result.ConsumerID}
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
