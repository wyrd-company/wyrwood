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
	return client.ApplyContext(context.Background())
}

func (client *Client) Keys() (KeysResult, error) {
	return client.KeysContext(context.Background())
}

func (client *Client) Status() (StatusResult, error) {
	return client.StatusContext(context.Background())
}

func (client *Client) Events(limit int) (EventsResult, error) {
	return client.EventsContext(context.Background(), limit)
}

// Configuration returns one coherent page. expectedRevision must be empty for
// offset zero and must be the first page's revision for every later page.
func (client *Client) Configuration(offset, limit int, expectedRevision string) (ConfigurationResult, error) {
	return client.ConfigurationContext(context.Background(), offset, limit, expectedRevision)
}

func (client *Client) SetUpstream(expectedRevision, upstream string) (ConfigurationChangeResult, error) {
	return client.SetUpstreamContext(context.Background(), expectedRevision, upstream)
}

func (client *Client) SetTimeouts(expectedRevision string, timeouts ConfigurationTimeouts) (ConfigurationChangeResult, error) {
	return client.SetTimeoutsContext(context.Background(), expectedRevision, timeouts)
}

func (client *Client) PutConsumer(expectedRevision string, consumerID *string, consumer ConfigurationConsumerInput) (ConfigurationChangeResult, error) {
	return client.PutConsumerContext(context.Background(), expectedRevision, consumerID, consumer)
}

func (client *Client) RetireConsumer(expectedRevision, consumerID string) (ConfigurationChangeResult, error) {
	return client.RetireConsumerContext(context.Background(), expectedRevision, consumerID)
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
