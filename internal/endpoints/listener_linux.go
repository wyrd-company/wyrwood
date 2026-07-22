//go:build linux

// ---
// relationships:
//   implements: linux-per-user-agent-proxy
//   uses: operational-events
// ---

package endpoints

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/wyrd-company/wyrwood/internal/agentconn"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/runtime"
	"golang.org/x/sys/unix"
)

const (
	initialAcceptBackoff = 5 * time.Millisecond
	maximumAcceptBackoff = 100 * time.Millisecond
)

type endpoint struct {
	manager  *Manager
	listener *net.UnixListener
	file     *endpointFile
	consumer runtime.Consumer
	ctx      context.Context
	cancel   context.CancelFunc

	mu          sync.Mutex
	connections map[io.Closer]struct{}
	closing     bool
	wg          sync.WaitGroup
}

func newEndpoint(manager *Manager, listener *net.UnixListener, file *endpointFile, consumer runtime.Consumer) *endpoint {
	ctx, cancel := context.WithCancel(context.Background())
	return &endpoint{
		manager:     manager,
		listener:    listener,
		file:        file,
		consumer:    consumer,
		ctx:         ctx,
		cancel:      cancel,
		connections: make(map[io.Closer]struct{}),
	}
}

func (endpoint *endpoint) start() {
	endpoint.wg.Add(1)
	go endpoint.accept()
}

func (endpoint *endpoint) accept() {
	defer endpoint.wg.Done()
	backoff := time.Duration(0)
	degraded := false
	defer func() {
		if degraded {
			endpoint.manager.transientListeners.Add(-1)
		}
	}()
	for {
		connection, err := endpoint.manager.deps.accept(endpoint.listener)
		if err != nil {
			if endpoint.isClosing() {
				return
			}
			if !temporaryAcceptError(err) {
				endpoint.manager.listenerError.Store(true)
				return
			}
			if !degraded {
				degraded = true
				endpoint.manager.transientListeners.Add(1)
			}
			if backoff == 0 {
				backoff = initialAcceptBackoff
			} else {
				backoff = min(backoff*2, maximumAcceptBackoff)
			}
			timer := time.NewTimer(backoff)
			select {
			case <-endpoint.ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
			continue
		}
		if degraded {
			degraded = false
			endpoint.manager.transientListeners.Add(-1)
		}
		backoff = 0
		endpoint.track(connection)
	}
}

func temporaryAcceptError(err error) bool {
	var networkError net.Error
	if errors.As(err, &networkError) && (networkError.Temporary() || networkError.Timeout()) {
		return true
	}
	return errors.Is(err, unix.EMFILE) || errors.Is(err, unix.ENFILE) ||
		errors.Is(err, unix.ENOMEM) || errors.Is(err, unix.ENOBUFS)
}

func (endpoint *endpoint) isClosing() bool {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	return endpoint.closing
}

func (endpoint *endpoint) connectionCount() int {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	return len(endpoint.connections)
}

func (endpoint *endpoint) track(connection *net.UnixConn) {
	endpoint.mu.Lock()
	if endpoint.closing {
		endpoint.mu.Unlock()
		_ = connection.Close()
		return
	}
	endpoint.connections[connection] = struct{}{}
	endpoint.wg.Add(1)
	endpoint.mu.Unlock()
	go endpoint.serve(connection)
}

func (endpoint *endpoint) serve(connection *net.UnixConn) {
	defer endpoint.wg.Done()
	defer func() {
		endpoint.mu.Lock()
		delete(endpoint.connections, connection)
		endpoint.mu.Unlock()
	}()
	endpoint.manager.record(events.Event{
		Timestamp:  endpoint.manager.deps.now(),
		ConsumerID: consumerID(endpoint.consumer.Socket()),
		Operation:  events.OperationConsumerConnect,
		Outcome:    events.OutcomeSucceeded,
		ErrorCode:  events.ErrorNone,
	})
	snapshot := endpoint.manager.store.Active()
	_ = agentconn.ServeObserved(
		endpoint.ctx, endpoint.manager.store, endpoint.consumer.Socket(), snapshot.Upstream(), snapshot.Timeouts(),
		connection, consumerID(endpoint.consumer.Socket()), endpoint.manager.record,
	)
}

func (endpoint *endpoint) closeConnections() {
	endpoint.mu.Lock()
	defer endpoint.mu.Unlock()
	for connection := range endpoint.connections {
		_ = connection.Close()
	}
}

func (endpoint *endpoint) stop() {
	endpoint.mu.Lock()
	if endpoint.closing {
		endpoint.mu.Unlock()
		endpoint.wg.Wait()
		return
	}
	endpoint.closing = true
	endpoint.cancel()
	_ = endpoint.listener.Close()
	for connection := range endpoint.connections {
		_ = connection.Close()
	}
	endpoint.mu.Unlock()
	endpoint.wg.Wait()
}
