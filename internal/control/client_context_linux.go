//go:build linux

// ---
// relationships:
//   implements: control-interface
// ---

package control

import "context"

// ConfigurationContext performs a coherent configuration-page request that
// can be interrupted by a closing interactive client.
func (client *Client) ConfigurationContext(ctx context.Context, offset, limit int, expectedRevision string) (ConfigurationResult, error) {
	request := Request{Version: Version, Operation: OperationConfiguration, Offset: &offset, Limit: &limit}
	if expectedRevision != "" {
		request.ExpectedRevision = &expectedRevision
	}
	response, err := client.callContext(ctx, request)
	if err != nil {
		return ConfigurationResult{}, err
	}
	return *response.Configuration, nil
}

// KeysContext performs a key projection request that can be interrupted by a
// closing interactive client.
func (client *Client) KeysContext(ctx context.Context) (KeysResult, error) {
	response, err := client.callContext(ctx, Request{Version: Version, Operation: OperationKeys})
	if err != nil {
		return KeysResult{}, err
	}
	return *response.Keys, nil
}

// StatusContext performs a status request that can be interrupted by a closing
// interactive client.
func (client *Client) StatusContext(ctx context.Context) (StatusResult, error) {
	response, err := client.callContext(ctx, Request{Version: Version, Operation: OperationStatus})
	if err != nil {
		return StatusResult{}, err
	}
	return *response.Status, nil
}

// EventsContext performs an event request that can be interrupted by a closing
// interactive client.
func (client *Client) EventsContext(ctx context.Context, limit int) (EventsResult, error) {
	response, err := client.callContext(ctx, Request{Version: Version, Operation: OperationEvents, Limit: &limit})
	if err != nil {
		return EventsResult{}, err
	}
	return *response.Events, nil
}

// ApplyContext asks the daemon to load the fixed durable configuration while
// allowing an interactive client to cancel its transport wait.
func (client *Client) ApplyContext(ctx context.Context) (ApplyResult, error) {
	response, err := client.callContext(ctx, Request{Version: Version, Operation: OperationApply})
	if err != nil {
		return ApplyResult{}, err
	}
	return *response.Apply, nil
}

func (client *Client) SetUpstreamContext(ctx context.Context, expectedRevision, upstream string) (ConfigurationChangeResult, error) {
	response, err := client.callContext(ctx, Request{
		Version: Version, Operation: OperationSetUpstream,
		ExpectedRevision: &expectedRevision, Upstream: &upstream,
	})
	if err != nil {
		return ConfigurationChangeResult{}, err
	}
	return *response.ConfigurationChange, nil
}

func (client *Client) SetTimeoutsContext(ctx context.Context, expectedRevision string, timeouts ConfigurationTimeouts) (ConfigurationChangeResult, error) {
	response, err := client.callContext(ctx, Request{
		Version: Version, Operation: OperationSetTimeouts,
		ExpectedRevision: &expectedRevision, Timeouts: &timeouts,
	})
	if err != nil {
		return ConfigurationChangeResult{}, err
	}
	return *response.ConfigurationChange, nil
}

func (client *Client) PutConsumerContext(ctx context.Context, expectedRevision string, consumerID *string, consumer ConfigurationConsumerInput) (ConfigurationChangeResult, error) {
	response, err := client.callContext(ctx, Request{
		Version: Version, Operation: OperationPutConsumer,
		ExpectedRevision: &expectedRevision, ConsumerID: consumerID, Consumer: &consumer,
	})
	if err != nil {
		return ConfigurationChangeResult{}, err
	}
	return *response.ConfigurationChange, nil
}

func (client *Client) RetireConsumerContext(ctx context.Context, expectedRevision, consumerID string) (ConfigurationChangeResult, error) {
	response, err := client.callContext(ctx, Request{
		Version: Version, Operation: OperationRetireConsumer,
		ExpectedRevision: &expectedRevision, ConsumerID: &consumerID,
	})
	if err != nil {
		return ConfigurationChangeResult{}, err
	}
	return *response.ConfigurationChange, nil
}
