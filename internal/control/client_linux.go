//go:build linux

// ---
// relationships:
//   implements: control-interface
// ---

package control

import (
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

func (client *Client) call(request Request) (Response, error) {
	deadline := time.Now().Add(client.timeout)
	dialer := net.Dialer{Timeout: client.timeout, Deadline: deadline}
	connection, err := dialer.Dial("unix", client.path)
	if err != nil {
		return Response{}, errors.New("connect to daemon control socket")
	}
	defer connection.Close()
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
