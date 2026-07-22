// ---
// relationships:
//   implements: operational-events
// ---

package events

import "time"

// HealthCategory is the closed health projection vocabulary.
type HealthCategory string

const (
	HealthUnknown  HealthCategory = "unknown"
	HealthHealthy  HealthCategory = "healthy"
	HealthDenied   HealthCategory = "denied"
	HealthDegraded HealthCategory = "degraded"
)

// Health is a categorical projection of the most recently recorded operation.
type Health struct {
	Category  HealthCategory
	ErrorCode ErrorCode
	Timestamp time.Time
}

// Recent returns at most limit events in durable write order, oldest first.
func (store *Store) Recent(limit int) []Event {
	store.mu.RLock()
	defer store.mu.RUnlock()

	if limit <= 0 || len(store.events) == 0 {
		return nil
	}
	start := len(store.events) - limit
	if start < 0 {
		start = 0
	}
	result := make([]Event, len(store.events)-start)
	for index := range result {
		result[index] = cloneEvent(store.events[start+index])
	}
	return result
}

// LastConsumerActivity returns each consumer's latest event timestamp.
func (store *Store) LastConsumerActivity() map[ConsumerID]time.Time {
	store.mu.RLock()
	defer store.mu.RUnlock()

	activity := make(map[ConsumerID]time.Time)
	for _, event := range store.events {
		current, exists := activity[event.ConsumerID]
		if !exists || event.Timestamp.After(current) {
			activity[event.ConsumerID] = event.Timestamp
		}
	}
	return activity
}

// Health returns the categorical result of the most recently written event.
func (store *Store) Health() Health {
	store.mu.RLock()
	defer store.mu.RUnlock()

	if len(store.events) == 0 {
		return Health{Category: HealthUnknown, ErrorCode: ErrorNone}
	}
	return projectHealth(store.events[len(store.events)-1])
}

// ConsumerHealth returns categorical health from each consumer's latest event.
func (store *Store) ConsumerHealth() map[ConsumerID]Health {
	store.mu.RLock()
	defer store.mu.RUnlock()

	health := make(map[ConsumerID]Health)
	for _, event := range store.events {
		health[event.ConsumerID] = projectHealth(event)
	}
	return health
}

func projectHealth(event Event) Health {
	category := HealthDegraded
	switch event.Outcome {
	case OutcomeSucceeded:
		category = HealthHealthy
	case OutcomeDenied:
		category = HealthDenied
	}
	return Health{
		Category:  category,
		ErrorCode: event.ErrorCode,
		Timestamp: event.Timestamp,
	}
}
