//go:build linux

// ---
// relationships:
//   implements: control-interface
// ---

package control

import (
	"context"
	"errors"
	"net"
	"time"
)

// ClientOperationTimeout bounds every complete CLI and TUI control exchange.
const ClientOperationTimeout = 65 * time.Second

// RemoteError is a stable categorical daemon rejection. It contains no raw
// daemon or upstream error text.
type RemoteError struct{ Code ErrorCode }

func (err *RemoteError) Error() string { return "daemon request failed: " + string(err.Code) }

// Client is the sole management-surface API for daemon state and operations.
type Client struct {
	path    string
	timeout time.Duration
}

func NewClient(path string) (*Client, error) {
	if path == "" {
		return nil, errors.New("control socket path is required")
	}
	return &Client{path: path, timeout: ClientOperationTimeout}, nil
}

func (client *Client) Apply() (ApplyResult, error) {
	response, err := client.call(Request{Version: Version, Operation: OperationApply})
	if err != nil {
		return ApplyResult{}, err
	}
	return *response.Apply, nil
}

func (client *Client) Keys() (KeysResult, error) {
	response, err := client.call(Request{Version: Version, Operation: OperationKeys})
	if err != nil {
		return KeysResult{}, err
	}
	return *response.Keys, nil
}

func (client *Client) Status() (StatusResult, error) {
	response, err := client.call(Request{Version: Version, Operation: OperationStatus})
	if err != nil {
		return StatusResult{}, err
	}
	return *response.Status, nil
}

func (client *Client) Events(limit int) (EventsResult, error) {
	response, err := client.call(Request{Version: Version, Operation: OperationEvents, Limit: &limit})
	if err != nil {
		return EventsResult{}, err
	}
	return *response.Events, nil
}

// Configuration returns one coherent page. expectedRevision must be empty for
// offset zero and must be the first page's revision for every later page.
func (client *Client) Configuration(offset, limit int, expectedRevision string) (ConfigurationResult, error) {
	request := Request{Version: Version, Operation: OperationConfiguration, Offset: &offset, Limit: &limit}
	if expectedRevision != "" {
		request.ExpectedRevision = &expectedRevision
	}
	response, err := client.call(request)
	if err != nil {
		return ConfigurationResult{}, err
	}
	return *response.Configuration, nil
}

func (client *Client) SetUpstream(expectedRevision, upstream string) (ConfigurationChangeResult, error) {
	response, err := client.call(Request{
		Version: Version, Operation: OperationSetUpstream,
		ExpectedRevision: &expectedRevision, Upstream: &upstream,
	})
	if err != nil {
		return ConfigurationChangeResult{}, err
	}
	return *response.ConfigurationChange, nil
}

func (client *Client) SetTimeouts(expectedRevision string, timeouts ConfigurationTimeouts) (ConfigurationChangeResult, error) {
	response, err := client.call(Request{
		Version: Version, Operation: OperationSetTimeouts,
		ExpectedRevision: &expectedRevision, Timeouts: &timeouts,
	})
	if err != nil {
		return ConfigurationChangeResult{}, err
	}
	return *response.ConfigurationChange, nil
}

func (client *Client) PutConsumer(expectedRevision string, consumerID *string, consumer ConfigurationConsumerInput) (ConfigurationChangeResult, error) {
	response, err := client.call(Request{
		Version: Version, Operation: OperationPutConsumer, ExpectedRevision: &expectedRevision,
		ConsumerID: consumerID, Consumer: &consumer,
	})
	if err != nil {
		return ConfigurationChangeResult{}, err
	}
	return *response.ConfigurationChange, nil
}

func (client *Client) RetireConsumer(expectedRevision, consumerID string) (ConfigurationChangeResult, error) {
	response, err := client.call(Request{
		Version: Version, Operation: OperationRetireConsumer,
		ExpectedRevision: &expectedRevision, ConsumerID: &consumerID,
	})
	if err != nil {
		return ConfigurationChangeResult{}, err
	}
	return *response.ConfigurationChange, nil
}

func (client *Client) call(request Request) (Response, error) {
	return client.callContext(context.Background(), request)
}

func (client *Client) callContext(ctx context.Context, request Request) (Response, error) {
	deadline := time.Now().Add(client.timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	dialer := net.Dialer{Timeout: client.timeout, Deadline: deadline}
	connection, err := dialer.DialContext(ctx, "unix", client.path)
	if err != nil {
		return Response{}, errors.New("connect to daemon control socket")
	}
	defer connection.Close()
	stopCancellation := context.AfterFunc(ctx, func() {
		_ = connection.SetDeadline(time.Now())
	})
	defer stopCancellation()
	if err := connection.SetDeadline(deadline); err != nil {
		return Response{}, errors.New("set daemon control deadline")
	}
	if err := writeJSONFrame(connection, MaximumRequestBytes, request); err != nil {
		return Response{}, err
	}
	var response Response
	if err := readJSONFrame(connection, MaximumResponseBytes, &response); err != nil {
		return Response{}, err
	}
	if err := validateResponse(request, response); err != nil {
		return Response{}, err
	}
	if !response.OK {
		return Response{}, &RemoteError{Code: response.Error}
	}
	return response, nil
}
