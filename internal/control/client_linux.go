//go:build linux

// ---
// relationships:
//   implements: control-interface
// ---

package control

import (
	"errors"
	"fmt"
	"net"
	"time"
	"unicode/utf8"
)

const clientOperationTimeout = 65 * time.Second

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
	return &Client{path: path, timeout: clientOperationTimeout}, nil
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
	connection, err := net.DialTimeout("unix", client.path, client.timeout)
	if err != nil {
		return Response{}, errors.New("connect to daemon control socket")
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(client.timeout))
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

func validateResponse(request Request, response Response) error {
	if response.Version != Version {
		return errors.New("daemon control protocol version mismatch")
	}
	results := 0
	if response.Apply != nil {
		results++
	}
	if response.Keys != nil {
		results++
	}
	if response.Status != nil {
		results++
	}
	if response.Events != nil {
		results++
	}
	if !response.OK {
		if !validErrorCode(response.Error) || response.Error == ErrorNone || results != 0 {
			return errors.New("invalid daemon error response")
		}
		return nil
	}
	if response.Error != ErrorNone || results != 1 {
		return errors.New("invalid daemon success response")
	}
	valid := request.Operation == OperationApply && response.Apply != nil ||
		request.Operation == OperationKeys && response.Keys != nil ||
		request.Operation == OperationStatus && response.Status != nil ||
		request.Operation == OperationEvents && response.Events != nil
	if !valid {
		return fmt.Errorf("daemon returned the wrong operation result")
	}
	if response.Keys != nil && len(response.Keys.Keys) > MaximumProjectedKeys ||
		response.Status != nil && len(response.Status.Consumers) > MaximumProjectedConsumers ||
		response.Events != nil && (request.Limit == nil || len(response.Events.Events) > *request.Limit) {
		return errors.New("daemon response exceeds the operation bound")
	}
	if response.Status != nil {
		if !validHealth(response.Status.Daemon) || !validHealth(response.Status.Upstream) {
			return errors.New("daemon returned an invalid health category")
		}
		for _, consumer := range response.Status.Consumers {
			if consumer.Name == "" || !utf8.ValidString(consumer.Name) || utf8.RuneCountInString(consumer.Name) > MaximumConsumerNameCharacters ||
				!validHealth(consumer.Listener) || consumer.ActiveConnections < 0 {
				return errors.New("daemon returned an invalid consumer status")
			}
		}
	}
	return nil
}

func validHealth(health HealthCategory) bool {
	switch health {
	case HealthHealthy, HealthDegraded, HealthUnavailable:
		return true
	default:
		return false
	}
}

func validErrorCode(code ErrorCode) bool {
	switch code {
	case ErrorNone, ErrorBadRequest, ErrorUnsupportedVersion, ErrorApplyInvalid,
		ErrorApplyFailed, ErrorUpstreamUnavailable, ErrorResourceLimit, ErrorInternal:
		return true
	default:
		return false
	}
}
