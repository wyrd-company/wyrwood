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
