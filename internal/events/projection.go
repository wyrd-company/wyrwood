// ---
// relationships:
//   implements: operational-events
// ---

package events

// HealthCategory is the closed health projection vocabulary.
type HealthCategory string

const (
	HealthUnknown  HealthCategory = "unknown"
	HealthHealthy  HealthCategory = "healthy"
	HealthDenied   HealthCategory = "denied"
	HealthDegraded HealthCategory = "degraded"
)

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
	return cloneEvents(store.events[start:])
}

// BindingHealth returns categorical health from each binding's most recent
// retained event. Events without a binding do not contribute.
func (store *Store) BindingHealth() map[string]HealthCategory {
	store.mu.RLock()
	defer store.mu.RUnlock()

	health := make(map[string]HealthCategory)
	for _, event := range store.events {
		if event.Binding != "" {
			health[event.Binding] = Project(event)
		}
	}
	return health
}

// Project maps one event outcome onto the health vocabulary.
func Project(event Event) HealthCategory {
	switch event.Outcome {
	case OutcomeOK:
		return HealthHealthy
	case OutcomeDenied:
		return HealthDenied
	default:
		return HealthDegraded
	}
}
