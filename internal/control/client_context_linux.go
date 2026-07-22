//go:build linux

// ---
// relationships:
//   implements: control-interface
// ---

package control

import "context"

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
