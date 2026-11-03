// ---
// relationships:
//   verifies:
//     - controller
//     - agent
// ---

package baotest

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// failIfSlower bounds the startup cases that must not spend the whole budget.
const failIfSlower = 10 * time.Second

// scriptedExecutable writes a shell script that stands in for bao.
func scriptedExecutable(t *testing.T, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scripted-server")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

// addressSequence returns each address in turn, then real free addresses.
func addressSequence(addresses ...string) (func() (string, error), *atomic.Int32) {
	var calls atomic.Int32
	return func() (string, error) {
		call := int(calls.Add(1))
		if call <= len(addresses) {
			return addresses[call-1], nil
		}
		return reserveLoopbackAddress()
	}, &calls
}

func assertHealthy(t *testing.T, server *devServer) {
	t.Helper()
	response, err := http.Get(server.url() + "/v1/sys/health")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("health status = %d", response.StatusCode)
	}
}

func assertProcessGone(t *testing.T, pid int) {
	t.Helper()
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("process %d remains: %v", pid, err)
	}
}

// TestStartMovesOffAddressHeldByAHealthySocket holds the address before the
// real server starts. The holder answers health 200, so this also proves that
// a socket present before the child starts receives no request and is not taken
// for the server.
func TestStartMovesOffAddressHeldByAHealthySocket(t *testing.T) {
	executable := Executable(t)
	var requests atomic.Int32
	holder := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusOK)
	}))
	defer holder.Close()
	held := holder.Listener.Addr().String()

	reserve, _ := addressSequence(held)
	server, taken, err := startDevServer(executable, t.TempDir(), reserve, startBudget)
	if err != nil {
		t.Fatal(err)
	}
	defer server.stop()

	if len(taken) != 1 || taken[0] != held {
		t.Fatalf("taken = %v, want [%s]", taken, held)
	}
	if server.address == held {
		t.Fatalf("server kept the held address %s", held)
	}
	assertHealthy(t, server)
	if got := requests.Load(); got != 0 {
		t.Fatalf("holder received %d requests", got)
	}
}

// TestStartKeepsAddressWhenOnlyTheClusterPortIsHeld proves that OpenBao's
// non-fatal cluster listener failure does not cost the server its address.
func TestStartKeepsAddressWhenOnlyTheClusterPortIsHeld(t *testing.T) {
	executable := Executable(t)
	var address string
	var holder net.Listener
	for attempt := 0; attempt < 20 && holder == nil; attempt++ {
		candidate, err := reserveLoopbackAddress()
		if err != nil {
			t.Fatal(err)
		}
		host, port, err := net.SplitHostPort(candidate)
		if err != nil {
			t.Fatal(err)
		}
		number, err := strconv.Atoi(port)
		if err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(number+1)))
		if err == nil {
			address, holder = candidate, listener
		}
	}
	if holder == nil {
		t.Fatal("no address with a free cluster port")
	}
	defer holder.Close()

	reserve, calls := addressSequence(address)
	server, taken, err := startDevServer(executable, t.TempDir(), reserve, startBudget)
	if err != nil {
		t.Fatal(err)
	}
	defer server.stop()

	if server.address != address || len(taken) != 0 || calls.Load() != 1 {
		t.Fatalf("address = %s, taken = %v, reservations = %d; want %s, none, 1", server.address, taken, calls.Load(), address)
	}
	if !server.output.contains("error starting listener") {
		t.Fatalf("cluster port collision did not occur: %s", server.output.String())
	}
	assertHealthy(t, server)
}

// TestStartFailsAtOnceOnAnotherStartupFailure keeps real startup failures
// visible, including a collision message for an address the server was not
// told to bind.
func TestStartFailsAtOnceOnAnotherStartupFailure(t *testing.T) {
	for name, message := range map[string]string{
		"unrelated failure": "Error parsing listener configuration.",
		"other address":     "Error initializing listener of type tcp: listen tcp 127.0.0.1:1: bind: address already in use",
	} {
		t.Run(name, func(t *testing.T) {
			executable := scriptedExecutable(t, fmt.Sprintf("echo %q\nexit 1", message))
			reserve, calls := addressSequence()
			began := time.Now()
			server, taken, err := startDevServer(executable, t.TempDir(), reserve, startBudget)
			if err == nil {
				server.stop()
				t.Fatal("start succeeded")
			}
			if errors.Is(err, errAddressTaken) {
				t.Fatalf("error classified as a collision: %v", err)
			}
			if !strings.Contains(err.Error(), message) {
				t.Fatalf("error lost the output: %v", err)
			}
			if calls.Load() != 1 || len(taken) != 0 {
				t.Fatalf("reservations = %d, taken = %v; want 1, none", calls.Load(), taken)
			}
			if elapsed := time.Since(began); elapsed > failIfSlower {
				t.Fatalf("failure took %s", elapsed)
			}
		})
	}
}

// TestStartGivesUpWhenEveryAddressStaysHeld proves that reallocation ends
// inside the budget and retains the cause.
func TestStartGivesUpWhenEveryAddressStaysHeld(t *testing.T) {
	executable := Executable(t)
	holder, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	held := holder.Addr().String()

	var attempts atomic.Int32
	const budget = time.Second
	began := time.Now()
	server, taken, err := startDevServer(executable, t.TempDir(), func() (string, error) {
		attempts.Add(1)
		return held, nil
	}, budget)
	elapsed := time.Since(began)
	if err == nil {
		server.stop()
		t.Fatal("start succeeded on a held address")
	}
	if !errors.Is(err, errAddressTaken) || !strings.Contains(err.Error(), held) {
		t.Fatalf("error lost the cause: %v", err)
	}
	if attempts.Load() < 2 || int(attempts.Load())-len(taken) > 1 {
		t.Fatalf("attempts = %d, taken = %d", attempts.Load(), len(taken))
	}
	if elapsed < budget || elapsed > failIfSlower {
		t.Fatalf("gave up after %s, budget %s", elapsed, budget)
	}
}

// TestStartReapsAChildThatNeverBecomesReady proves the deadline path leaves no
// child, including a child that reports it started and never answers health.
// The short budget only shortens the wait for these scripted children.
func TestStartReapsAChildThatNeverBecomesReady(t *testing.T) {
	for name, line := range map[string]string{
		"never reports started":   "still-starting",
		"reports without serving": serverStartedLine,
	} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			executable := scriptedExecutable(t, fmt.Sprintf("echo $$ > \"$HOME/pid\"\necho %q\nexec sleep 300", line))
			reserve, _ := addressSequence()
			server, _, err := startDevServer(executable, home, reserve, 500*time.Millisecond)
			if err == nil {
				server.stop()
				t.Fatal("start succeeded")
			}
			if !strings.Contains(err.Error(), "did not start") || !strings.Contains(err.Error(), line) {
				t.Fatalf("error lost the output: %v", err)
			}
			content, err := os.ReadFile(filepath.Join(home, "pid"))
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
			if err != nil {
				t.Fatal(err)
			}
			assertProcessGone(t, pid)
		})
	}
}

// TestStartStopsTheServerWhenTheTestEnds proves Start registers the cleanup.
func TestStartStopsTheServerWhenTheTestEnds(t *testing.T) {
	Executable(t)
	var address string
	t.Run("started", func(t *testing.T) {
		server := Start(t)
		address = strings.TrimPrefix(server.Address, "http://")
	})
	connection, err := net.DialTimeout("tcp", address, time.Second)
	if err == nil {
		_ = connection.Close()
		t.Fatalf("server at %s still accepts connections", address)
	}
}
