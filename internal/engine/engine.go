// ---
// relationships:
//   implements: agent
//   assumes: docker-engine-is-the-only-runtime
// ---

// Package engine is the agent's Docker Engine boundary: read operations for
// observation and the one write path recreate needs. Errors are categorical.
package engine

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ErrUnavailable means the engine could not be reached or answered abnormally.
var ErrUnavailable = errors.New("engine unavailable")

// ErrNotFound means the container does not exist.
var ErrNotFound = errors.New("container not found")

// Summary is one entry of the container list.
type Summary struct {
	ID string `json:"Id"`
}

// Mount is one inspected mount.
type Mount struct {
	Type        string `json:"Type"`
	Name        string `json:"Name"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

// Container is the parsed inspect result plus the raw sections recreate
// needs to reproduce the container faithfully.
type Container struct {
	ID    string `json:"Id"`
	Name  string `json:"Name"`
	Image string `json:"Image"`
	State struct {
		Status string `json:"Status"`
	} `json:"State"`
	Config struct {
		Image       string            `json:"Image"`
		Labels      map[string]string `json:"Labels"`
		Env         []string          `json:"Env"`
		StopTimeout *int              `json:"StopTimeout"`
	} `json:"Config"`
	Mounts []Mount `json:"Mounts"`

	Raw struct {
		Config          json.RawMessage `json:"Config"`
		HostConfig      json.RawMessage `json:"HostConfig"`
		NetworkSettings json.RawMessage `json:"NetworkSettings"`
	} `json:"-"`
}

// ShortName returns the container name without the engine's leading slash.
func (container Container) ShortName() string { return strings.TrimPrefix(container.Name, "/") }

// EnvValue returns the value of an environment name and whether it is set.
func (container Container) EnvValue(name string) (string, bool) {
	for _, entry := range container.Config.Env {
		key, value, found := strings.Cut(entry, "=")
		if key == name {
			return value, found
		}
	}
	return "", false
}

// Event is an engine container event used as a reconcile hint.
type Event struct {
	ID     string
	Action string
}

// Engine is the agent's view of Docker Engine.
type Engine interface {
	List(ctx context.Context) ([]Summary, error)
	Inspect(ctx context.Context, id string) (Container, error)
	Events(ctx context.Context) (<-chan Event, <-chan error)
	ImageID(ctx context.Context, reference string) (string, error)
	Stop(ctx context.Context, id string, timeout time.Duration) error
	Remove(ctx context.Context, id string) error
	Create(ctx context.Context, name string, body []byte) (string, error)
	Start(ctx context.Context, id string) error
}

// Client talks to Docker Engine over its Unix socket.
type Client struct {
	http *http.Client
}

// NewClient returns a client for the engine socket at path.
func NewClient(path string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", path)
		},
		MaxIdleConns:    4,
		IdleConnTimeout: 30 * time.Second,
	}
	return &Client{http: &http.Client{Transport: transport}}
}

func (client *Client) do(ctx context.Context, method, path string, query url.Values, body []byte) (*http.Response, error) {
	target := "http://engine" + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(ctx, method, target, reader)
	if err != nil {
		return nil, ErrUnavailable
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := client.http.Do(request)
	if err != nil {
		return nil, ErrUnavailable
	}
	return response, nil
}

func (client *Client) decode(ctx context.Context, path string, query url.Values, destination any) error {
	response, err := client.do(ctx, http.MethodGet, path, query, nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if response.StatusCode != http.StatusOK {
		return ErrUnavailable
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 64<<20)).Decode(destination); err != nil {
		return ErrUnavailable
	}
	return nil
}

// List returns every container, running or not.
func (client *Client) List(ctx context.Context) ([]Summary, error) {
	var summaries []Summary
	err := client.decode(ctx, "/containers/json", url.Values{"all": {"1"}}, &summaries)
	return summaries, err
}

// Inspect returns one container's inspect result.
func (client *Client) Inspect(ctx context.Context, id string) (Container, error) {
	var raw json.RawMessage
	if err := client.decode(ctx, "/containers/"+url.PathEscape(id)+"/json", nil, &raw); err != nil {
		return Container{}, err
	}
	return ParseInspect(raw)
}

// ParseInspect parses raw inspect output.
func ParseInspect(raw []byte) (Container, error) {
	var container Container
	if err := json.Unmarshal(raw, &container); err != nil {
		return Container{}, ErrUnavailable
	}
	var sections struct {
		Config          json.RawMessage `json:"Config"`
		HostConfig      json.RawMessage `json:"HostConfig"`
		NetworkSettings json.RawMessage `json:"NetworkSettings"`
	}
	if err := json.Unmarshal(raw, &sections); err != nil {
		return Container{}, ErrUnavailable
	}
	container.Raw.Config = sections.Config
	container.Raw.HostConfig = sections.HostConfig
	container.Raw.NetworkSettings = sections.NetworkSettings
	return container, nil
}

// Events streams container create, start, die, destroy, and rename events
// until ctx ends. The error channel receives one value when the stream ends.
func (client *Client) Events(ctx context.Context) (<-chan Event, <-chan error) {
	stream := make(chan Event, 64)
	failure := make(chan error, 1)
	go func() {
		defer close(stream)
		filters, _ := json.Marshal(map[string][]string{
			"type":  {"container"},
			"event": {"create", "start", "die", "destroy", "rename"},
		})
		response, err := client.do(ctx, http.MethodGet, "/events", url.Values{"filters": {string(filters)}}, nil)
		if err != nil {
			failure <- err
			return
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			failure <- ErrUnavailable
			return
		}
		scanner := bufio.NewScanner(response.Body)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		for scanner.Scan() {
			var message struct {
				Action string `json:"Action"`
				Actor  struct {
					ID string `json:"ID"`
				} `json:"Actor"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &message); err != nil || message.Actor.ID == "" {
				continue
			}
			select {
			case stream <- Event{ID: message.Actor.ID, Action: message.Action}:
			case <-ctx.Done():
				failure <- ctx.Err()
				return
			}
		}
		if ctx.Err() != nil {
			failure <- ctx.Err()
			return
		}
		failure <- ErrUnavailable
	}()
	return stream, failure
}

// ImageID resolves an image reference to its identifier.
func (client *Client) ImageID(ctx context.Context, reference string) (string, error) {
	var image struct {
		ID string `json:"Id"`
	}
	if err := client.decode(ctx, "/images/"+url.PathEscape(reference)+"/json", nil, &image); err != nil {
		return "", err
	}
	return image.ID, nil
}

func (client *Client) expect(ctx context.Context, method, path string, query url.Values, body []byte, accepted ...int) (*http.Response, error) {
	response, err := client.do(ctx, method, path, query, body)
	if err != nil {
		return nil, err
	}
	for _, status := range accepted {
		if response.StatusCode == status {
			return response, nil
		}
	}
	_ = response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return nil, ErrNotFound
	}
	return nil, ErrUnavailable
}

// Stop stops a container, waiting at most timeout before the engine kills it.
func (client *Client) Stop(ctx context.Context, id string, timeout time.Duration) error {
	response, err := client.expect(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/stop",
		url.Values{"t": {strconv.Itoa(int(timeout / time.Second))}}, nil, http.StatusNoContent, http.StatusNotModified)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

// Remove removes a container without removing its volumes.
func (client *Client) Remove(ctx context.Context, id string) error {
	response, err := client.expect(ctx, http.MethodDelete, "/containers/"+url.PathEscape(id),
		url.Values{"v": {"0"}, "force": {"0"}}, nil, http.StatusNoContent)
	if err != nil {
		return err
	}
	return response.Body.Close()
}

// Create creates a container with name from a create request body.
func (client *Client) Create(ctx context.Context, name string, body []byte) (string, error) {
	response, err := client.expect(ctx, http.MethodPost, "/containers/create", url.Values{"name": {name}}, body, http.StatusCreated)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	var created struct {
		ID string `json:"Id"`
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&created); err != nil || created.ID == "" {
		return "", ErrUnavailable
	}
	return created.ID, nil
}

// Start starts a container.
func (client *Client) Start(ctx context.Context, id string) error {
	response, err := client.expect(ctx, http.MethodPost, "/containers/"+url.PathEscape(id)+"/start", nil, nil,
		http.StatusNoContent, http.StatusNotModified)
	if err != nil {
		return err
	}
	return response.Body.Close()
}
