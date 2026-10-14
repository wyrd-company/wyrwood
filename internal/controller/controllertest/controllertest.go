// ---
// relationships:
//   verifies: controller
// ---

// Package controllertest runs a real controller against an OpenBao dev
// server for agent and integration tests.
package controllertest

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/openbao/baotest"
)

// Controller is a running test controller.
type Controller struct {
	*controller.Controller
	Bao         *baotest.Server
	SSHAddress  string
	URL         string
	Fingerprint string
	stop        context.CancelFunc
	done        chan error
}

// FreeAddress returns an unused loopback address.
func FreeAddress(t testing.TB) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

// Start runs a controller with state in a temporary directory.
func Start(t testing.TB, bao *baotest.Server) *Controller {
	t.Helper()
	return StartIn(t, bao, t.TempDir(), FreeAddress(t))
}

// StartIn runs a controller with the given state directory and SSH address.
func StartIn(t testing.TB, bao *baotest.Server, state, sshAddress string) *Controller {
	t.Helper()
	return StartConfigured(t, bao, state, sshAddress, nil, nil)
}

// StartConfigured runs a controller after configure adjusts its
// configuration, serving HTTP with serveHTTP when it is non-nil.
func StartConfigured(t testing.TB, bao *baotest.Server, state, sshAddress string, configure func(*config.Controller),
	serveHTTP func(*controller.Controller) func(context.Context) error) *Controller {
	t.Helper()
	roleID, secretFile := bao.ControllerCredentials(t)
	configuration := config.Controller{
		HTTPListen: FreeAddress(t), SSHListen: sshAddress, StateDirectory: state, SessionTTL: time.Hour,
		OpenBao: config.ControllerOpenBao{Address: bao.Address, Namespace: bao.Namespace, AppRoleMount: "approle", RoleID: roleID,
			SecretIDFile: secretFile, TransitMount: "transit", SSHMount: "ssh"},
	}
	if configure != nil {
		configure(&configuration)
	}
	instance, err := controller.New(configuration, controller.Options{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	running := &Controller{Controller: instance, Bao: bao, SSHAddress: sshAddress, URL: "ssh://" + sshAddress, stop: cancel, done: make(chan error, 1)}
	var serve func(context.Context) error
	if serveHTTP != nil {
		serve = serveHTTP(instance)
	}
	go func() { running.done <- instance.Run(ctx, serve) }()
	t.Cleanup(running.Stop)
	deadline := time.Now().Add(10 * time.Second)
	for {
		connection, err := net.Dial("tcp", sshAddress)
		if err == nil {
			_ = connection.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("controller did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}
	running.Fingerprint, err = controller.HostKeyFingerprint(state)
	if err != nil {
		t.Fatal(err)
	}
	return running
}

// Stop stops the controller and closes its state. It is safe to call twice.
func (running *Controller) Stop() {
	if running.stop == nil {
		return
	}
	running.stop()
	<-running.done
	_ = running.Close()
	running.stop = nil
}
