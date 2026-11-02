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
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const (
	// startBudget bounds every attempt of one Start together.
	startBudget = 20 * time.Second
	// startPollInterval spaces the checks of a starting server.
	startPollInterval = 100 * time.Millisecond
	// serverStartedLine is printed by OpenBao after its listeners are bound.
	serverStartedLine = "==> OpenBao server started!"
)

// errAddressTaken reports that the server exited because another socket held
// the exact address it was told to bind.
var errAddressTaken = errors.New("address taken before the OpenBao dev server bound it")

// devServer is one running OpenBao child process.
type devServer struct {
	address string
	command *exec.Cmd
	output  *lockedBuffer
	exited  chan struct{}
}

// startDevServer starts a server on an address from reserve. OpenBao cannot
// report the port it binds for port 0, so reserve picks the port, and another
// socket can take it before the server binds it. When that exact collision
// makes the server exit, startDevServer tries a new address inside budget and
// returns the lost addresses. Any other failure ends the start at once, and the
// deadline ends the attempts, with the last collision kept in the error. On an
// error, no child remains.
func startDevServer(executable, home string, reserve func() (string, error), budget time.Duration) (*devServer, []string, error) {
	deadline := time.Now().Add(budget)
	var taken []string
	var collision error
	for {
		address, err := reserve()
		if err != nil {
			return nil, taken, err
		}
		server, err := launchDevServer(executable, home, address)
		if err != nil {
			return nil, taken, err
		}
		err = server.waitUntilReady(deadline)
		if err == nil {
			return server, taken, nil
		}
		server.stop()
		if !errors.Is(err, errAddressTaken) {
			return nil, taken, errors.Join(err, collision)
		}
		taken = append(taken, address)
		collision = err
	}
}

// reserveLoopbackAddress returns a loopback address the kernel found free.
func reserveLoopbackAddress() (string, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer listener.Close()
	return listener.Addr().String(), nil
}

func launchDevServer(executable, home, address string) (*devServer, error) {
	output := &lockedBuffer{}
	command := exec.Command(executable, "server", "-dev", "-dev-root-token-id="+RootToken,
		"-dev-listen-address="+address, "-dev-no-store-token")
	command.Env = []string{"HOME=" + home, "PATH=" + os.Getenv("PATH")}
	command.Stdout = output
	command.Stderr = output
	if err := command.Start(); err != nil {
		return nil, err
	}
	server := &devServer{address: address, command: command, output: output, exited: make(chan struct{})}
	go func() {
		_ = command.Wait()
		close(server.exited)
	}()
	return server, nil
}

// waitUntilReady waits for this child to report that it started, and only
// then asks the address for health. A child that reports it started owns the
// address, so another socket on that address is never contacted or mistaken
// for this server.
func (server *devServer) waitUntilReady(deadline time.Time) error {
	for {
		if server.output.contains(serverStartedLine) && server.healthy(deadline) {
			return nil
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("OpenBao dev server did not start: %s", server.output.String())
		}
		select {
		case <-server.exited:
			return server.exitFailure()
		case <-time.After(startPollInterval):
		}
	}
}

// exitFailure classifies a child that has exited, after Wait has copied all
// of its output.
func (server *devServer) exitFailure() error {
	output := server.output.String()
	collision := "Error initializing listener of type tcp: listen tcp " + server.address + ": bind: address already in use"
	if strings.Contains(output, collision) {
		return fmt.Errorf("%w: %s", errAddressTaken, output)
	}
	return fmt.Errorf("OpenBao dev server exited during start: %s", output)
}

func (server *devServer) healthy(deadline time.Time) bool {
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return false
	}
	client := http.Client{Timeout: remaining}
	response, err := client.Get(server.url() + "/v1/sys/health")
	if err != nil {
		return false
	}
	_ = response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func (server *devServer) url() string {
	return "http://" + server.address
}

// stop kills the child and waits until it is reaped.
func (server *devServer) stop() {
	_ = server.command.Process.Kill()
	<-server.exited
}

// lockedBuffer collects child output while the start checks read it.
type lockedBuffer struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (buffer *lockedBuffer) Write(data []byte) (int, error) {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.buffer.Write(data)
}

func (buffer *lockedBuffer) String() string {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()
	return buffer.buffer.String()
}

func (buffer *lockedBuffer) contains(text string) bool {
	return strings.Contains(buffer.String(), text)
}
