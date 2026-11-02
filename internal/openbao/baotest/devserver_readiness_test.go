// ---
// relationships:
//   verifies:
//     - controller
//     - agent
// ---

package baotest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// transportFunc lets a test act at the point where a health answer returns.
type transportFunc func(*http.Request) (*http.Response, error)

func (function transportFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

// startedScript reports started and stays alive without binding anything.
const startedScript = "echo '" + serverStartedLine + "'\nexec sleep 300"

// launchUntilStarted launches a child and waits for its started line.
func launchUntilStarted(t *testing.T, executable, address string) *devServer {
	t.Helper()
	child, err := launchDevServer(executable, t.TempDir(), address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(child.stop)
	limit := time.Now().Add(startBudget)
	for !child.output.contains(serverStartedLine) {
		if !time.Now().Before(limit) {
			t.Fatalf("no started line: %s", child.output.String())
		}
		select {
		case <-child.exited:
			t.Fatalf("child exited: %s", child.output.String())
		case <-time.After(startPollInterval):
		}
	}
	return child
}

// assertExitFailure proves that readiness reports the child's exit, with its
// output, and not a collision.
func assertExitFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("readiness accepted an exited child")
	}
	if errors.Is(err, errAddressTaken) {
		t.Fatalf("exit classified as a collision: %v", err)
	}
	if !strings.Contains(err.Error(), "exited during start") || !strings.Contains(err.Error(), serverStartedLine) {
		t.Fatalf("error lost the exit or the output: %v", err)
	}
}

// TestReadinessDoesNotAskAReplacementAfterTheChildExited runs the schedule
// where a real child reports started and is reaped, then a replacement answers
// at its address with the child's own name, so only the exit checks can refuse.
func TestReadinessDoesNotAskAReplacementAfterTheChildExited(t *testing.T) {
	address, err := reserveLoopbackAddress()
	if err != nil {
		t.Fatal(err)
	}
	child := launchUntilStarted(t, Executable(t), address)
	child.stop()

	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	replacement := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		fmt.Fprintf(writer, `{"cluster_name":%q}`, child.name)
	}))
	replacement.Listener.Close()
	replacement.Listener = listener
	replacement.Start()
	defer replacement.Close()

	// The transport sees every attempt. The cancelled context can stop an attempt
	// before it reaches the replacement, which a count at the replacement misses.
	var attempts atomic.Int32
	child.client.Transport = transportFunc(func(request *http.Request) (*http.Response, error) {
		attempts.Add(1)
		return http.DefaultTransport.RoundTrip(request)
	})

	assertExitFailure(t, child.waitUntilReady(time.Now().Add(startBudget)))
	if got := attempts.Load(); got != 0 {
		t.Fatalf("readiness made %d health attempts after the exit", got)
	}
	if got := requests.Load(); got != 0 {
		t.Fatalf("replacement received %d requests", got)
	}

	// Negative control: the replacement was serving at the address.
	assertHealthy(t, child)
	if got := requests.Load(); got != 1 {
		t.Fatalf("replacement received %d requests after the control, want 1", got)
	}
}

// TestReadinessRejectsAnotherServerWhileTheChildRuns is the gap the exit checks
// cannot close: the exit is not visible yet and a real OpenBao answers health
// 200 at the address. The short budget only shortens the wait for this case.
func TestReadinessRejectsAnotherServerWhileTheChildRuns(t *testing.T) {
	executable := Executable(t)
	address, err := reserveLoopbackAddress()
	if err != nil {
		t.Fatal(err)
	}
	other := launchUntilStarted(t, executable, address)
	if err := other.waitUntilReady(time.Now().Add(startBudget)); err != nil {
		t.Fatal(err)
	}

	child, err := launchDevServer(scriptedExecutable(t, startedScript), t.TempDir(), address)
	if err != nil {
		t.Fatal(err)
	}
	defer child.stop()
	var answers atomic.Int32
	child.client.Transport = transportFunc(func(request *http.Request) (*http.Response, error) {
		response, err := http.DefaultTransport.RoundTrip(request)
		if err == nil && response.StatusCode == http.StatusOK {
			answers.Add(1)
		}
		return response, err
	})

	err = child.waitUntilReady(time.Now().Add(500 * time.Millisecond))
	if err == nil {
		t.Fatal("readiness accepted another server")
	}
	if !strings.Contains(err.Error(), "did not start") || !strings.Contains(err.Error(), serverStartedLine) {
		t.Fatalf("error lost the output: %v", err)
	}
	if answers.Load() == 0 {
		t.Fatal("the other server's health 200 never reached the check")
	}
}

// TestReadinessRejectsAnAnswerWhenTheChildExitsBeforeAcceptance returns the
// real child's own health answer after the child has been reaped, so only the
// check before acceptance can refuse it.
func TestReadinessRejectsAnAnswerWhenTheChildExitsBeforeAcceptance(t *testing.T) {
	address, err := reserveLoopbackAddress()
	if err != nil {
		t.Fatal(err)
	}
	child := launchUntilStarted(t, Executable(t), address)
	var answered atomic.Bool
	child.client.Transport = transportFunc(func(request *http.Request) (*http.Response, error) {
		response, err := http.DefaultTransport.RoundTrip(request)
		if err != nil {
			return nil, err
		}
		body, err := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if err != nil {
			return nil, err
		}
		answered.Store(response.StatusCode == http.StatusOK && bytes.Contains(body, []byte(child.name)))
		child.stop()
		response.Body = io.NopCloser(bytes.NewReader(body))
		return response, nil
	})

	assertExitFailure(t, child.waitUntilReady(time.Now().Add(startBudget)))
	if !answered.Load() {
		t.Fatal("the child's own health answer did not reach the check")
	}
}

// TestReadinessCancelsAPendingProbeWhenTheChildExits holds the health request
// at a real listener, ends the child, and proves that the request ends without
// waiting for the budget.
func TestReadinessCancelsAPendingProbeWhenTheChildExits(t *testing.T) {
	arrived := make(chan struct{}, 1)
	cancelled := make(chan struct{}, 1)
	release := make(chan struct{})
	holder := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		arrived <- struct{}{}
		select {
		case <-request.Context().Done():
			cancelled <- struct{}{}
		case <-release:
		}
	}))
	defer holder.Close()
	defer close(release)

	child, err := launchDevServer(scriptedExecutable(t, startedScript), t.TempDir(), holder.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer child.stop()
	result := make(chan error, 1)
	began := time.Now()
	go func() { result <- child.waitUntilReady(time.Now().Add(startBudget)) }()

	select {
	case <-arrived:
	case err := <-result:
		t.Fatalf("readiness ended before the probe arrived: %v", err)
	}
	child.stop()
	assertExitFailure(t, <-result)
	if elapsed := time.Since(began); elapsed > failIfSlower {
		t.Fatalf("readiness took %s", elapsed)
	}
	select {
	case <-cancelled:
	case <-time.After(failIfSlower):
		t.Fatal("the pending request was not cancelled")
	}
}

// TestReadinessRequiresAHealthyStatus proves that the name alone is not enough.
// The short budget only shortens the wait for this case.
func TestReadinessRequiresAHealthyStatus(t *testing.T) {
	var name atomic.Pointer[string]
	holder := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprintf(writer, `{"cluster_name":%q}`, *name.Load())
	}))
	defer holder.Close()
	child, err := launchDevServer(scriptedExecutable(t, startedScript), t.TempDir(), holder.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer child.stop()
	name.Store(&child.name)

	err = child.waitUntilReady(time.Now().Add(500 * time.Millisecond))
	if err == nil || !strings.Contains(err.Error(), "did not start") {
		t.Fatalf("error = %v, want did not start", err)
	}
}

// TestStartFailsAtOnceWhenTheChildExitsAfterReportingStarted proves that an exit
// after the started line is not retried on a new address, and that a health 200
// at the address does not hide it.
func TestStartFailsAtOnceWhenTheChildExitsAfterReportingStarted(t *testing.T) {
	holder := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(writer, `{"cluster_name":"another"}`)
	}))
	defer holder.Close()
	executable := scriptedExecutable(t, "echo '"+serverStartedLine+"'\nexit 1")
	reserve, calls := addressSequence(holder.Listener.Addr().String())

	server, taken, err := startDevServer(executable, t.TempDir(), reserve, startBudget)
	if err == nil {
		server.stop()
		t.Fatal("start succeeded")
	}
	assertExitFailure(t, err)
	if calls.Load() != 1 || len(taken) != 0 {
		t.Fatalf("reservations = %d, taken = %v; want 1, none", calls.Load(), taken)
	}
}
