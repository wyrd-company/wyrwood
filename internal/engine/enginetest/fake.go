// ---
// relationships:
//   verifies: agent
// ---

// Package enginetest provides an in-memory engine for agent tests.
package enginetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"sync"
	"time"

	"github.com/wyrd-company/wyrwood/internal/engine"
)

// Fake is an in-memory engine. Create records the request body and makes a
// container from it.
type Fake struct {
	mu         sync.Mutex
	containers map[string]engine.Container
	order      []string
	listeners  []chan engine.Event
	Calls      []string
	Created    [][]byte
	FailCreate int
	FailRemove int
}

// New returns an empty fake engine.
func New() *Fake { return &Fake{containers: map[string]engine.Container{}} }

// NewID returns a random container identifier.
func NewID() string {
	var data [32]byte
	_, _ = rand.Read(data[:])
	return hex.EncodeToString(data[:])
}

// Add inserts a container and emits a create event.
func (fake *Fake) Add(container engine.Container) {
	if container.ID == "" {
		container.ID = NewID()
	}
	if container.Raw.Config == nil {
		config, _ := json.Marshal(map[string]any{"Image": container.Config.Image, "Labels": container.Config.Labels, "Env": container.Config.Env})
		container.Raw.Config = config
	}
	if container.Raw.HostConfig == nil {
		container.Raw.HostConfig = json.RawMessage(`{}`)
	}
	fake.mu.Lock()
	fake.containers[container.ID] = container
	fake.order = append(fake.order, container.ID)
	fake.mu.Unlock()
	fake.emit(engine.Event{ID: container.ID, Action: "create"})
}

// Destroy removes a container and emits a destroy event.
func (fake *Fake) Destroy(id string) {
	fake.mu.Lock()
	delete(fake.containers, id)
	fake.mu.Unlock()
	fake.emit(engine.Event{ID: id, Action: "destroy"})
}

// ByName returns the container with name.
func (fake *Fake) ByName(name string) (engine.Container, bool) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, container := range fake.containers {
		if container.ShortName() == name {
			return container, true
		}
	}
	return engine.Container{}, false
}

func (fake *Fake) emit(event engine.Event) {
	fake.mu.Lock()
	listeners := append([]chan engine.Event(nil), fake.listeners...)
	fake.mu.Unlock()
	for _, listener := range listeners {
		select {
		case listener <- event:
		case <-time.After(time.Second):
		}
	}
}

func (fake *Fake) call(name string) {
	fake.mu.Lock()
	fake.Calls = append(fake.Calls, name)
	fake.mu.Unlock()
}

// CallLog returns the recorded write calls.
func (fake *Fake) CallLog() []string {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	return append([]string(nil), fake.Calls...)
}

func (fake *Fake) List(context.Context) ([]engine.Summary, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	var summaries []engine.Summary
	for _, id := range fake.order {
		if _, ok := fake.containers[id]; ok {
			summaries = append(summaries, engine.Summary{ID: id})
		}
	}
	return summaries, nil
}

func (fake *Fake) Inspect(_ context.Context, id string) (engine.Container, error) {
	fake.mu.Lock()
	defer fake.mu.Unlock()
	container, ok := fake.containers[id]
	if !ok {
		for _, candidate := range fake.containers {
			if candidate.ShortName() == id {
				return candidate, nil
			}
		}
		return engine.Container{}, engine.ErrNotFound
	}
	return container, nil
}

func (fake *Fake) Events(ctx context.Context) (<-chan engine.Event, <-chan error) {
	stream := make(chan engine.Event, 64)
	failure := make(chan error, 1)
	fake.mu.Lock()
	fake.listeners = append(fake.listeners, stream)
	fake.mu.Unlock()
	go func() {
		<-ctx.Done()
		failure <- ctx.Err()
	}()
	return stream, failure
}

func (fake *Fake) ImageID(context.Context, string) (string, error) { return "sha256:image", nil }

func (fake *Fake) Stop(_ context.Context, id string, _ time.Duration) error {
	fake.call("stop")
	fake.mu.Lock()
	container, ok := fake.containers[id]
	if ok {
		container.State.Status = "exited"
		fake.containers[id] = container
	}
	fake.mu.Unlock()
	if !ok {
		return engine.ErrNotFound
	}
	return nil
}

func (fake *Fake) Remove(_ context.Context, id string) error {
	fake.call("remove")
	fake.mu.Lock()
	if fake.FailRemove > 0 {
		fake.FailRemove--
		fake.mu.Unlock()
		return engine.ErrUnavailable
	}
	fake.mu.Unlock()
	fake.Destroy(id)
	return nil
}

func (fake *Fake) Create(_ context.Context, name string, body []byte) (string, error) {
	fake.call("create")
	fake.mu.Lock()
	if fake.FailCreate > 0 {
		fake.FailCreate--
		fake.mu.Unlock()
		return "", engine.ErrUnavailable
	}
	fake.Created = append(fake.Created, body)
	fake.mu.Unlock()
	var request struct {
		Image  string            `json:"Image"`
		Labels map[string]string `json:"Labels"`
		Env    []string          `json:"Env"`
		Host   struct {
			Mounts []struct {
				Source string `json:"Source"`
				Target string `json:"Target"`
			} `json:"Mounts"`
		} `json:"HostConfig"`
	}
	if err := json.Unmarshal(body, &request); err != nil {
		return "", engine.ErrUnavailable
	}
	container := engine.Container{ID: NewID(), Name: "/" + name, Image: "sha256:image"}
	container.State.Status = "created"
	container.Config.Image = request.Image
	container.Config.Labels = request.Labels
	container.Config.Env = request.Env
	for _, mount := range request.Host.Mounts {
		container.Mounts = append(container.Mounts, engine.Mount{Type: "bind", Source: mount.Source, Destination: mount.Target, RW: true})
	}
	container.Raw.Config = body
	container.Raw.HostConfig = json.RawMessage(`{}`)
	fake.Add(container)
	return container.ID, nil
}

func (fake *Fake) Start(_ context.Context, id string) error {
	fake.call("start")
	fake.mu.Lock()
	container, ok := fake.containers[id]
	if ok {
		container.State.Status = "running"
		fake.containers[id] = container
	}
	fake.mu.Unlock()
	if !ok {
		return engine.ErrNotFound
	}
	fake.emit(engine.Event{ID: id, Action: "start"})
	return nil
}
