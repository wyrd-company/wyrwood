// ---
// relationships:
//   implements: controller
//   uses:
//     - agent-controller-protocol
//     - operational-events
// ---

// Package controller composes the controller: durable state, the OpenBao
// manager, the agent SSH server and sessions, operator operations, and
// operational events.
package controller

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/controller/store"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

const (
	eventRetention      = 10_000
	openBaoTimeout      = 10 * time.Second
	credentialWrapTTL   = 2 * time.Minute
	helloTimeout        = 10 * time.Second
	maximumPendingKeys  = 256
	loginRetryInterval  = 15 * time.Second
	operationTimeout    = 15 * time.Second
	sessionOpenBaoGrace = 5 * time.Second
)

// OpenBao is the subset of the OpenBao manager the controller uses, so tests
// can substitute it.
type OpenBao interface {
	Login(ctx context.Context) error
	Maintain(ctx context.Context, retry time.Duration)
	Mounts() openbao.Mounts
	WritePolicy(ctx context.Context, name, hcl string) error
	WriteRole(ctx context.Context, role, policyName string, tokenTTL time.Duration) error
	DeleteRole(ctx context.Context, role string) error
	RoleID(ctx context.Context, role string) (string, error)
	WrappedSecretID(ctx context.Context, role string, wrapTTL time.Duration) (string, error)
	TransitKeyExists(ctx context.Context, name string) (bool, error)
	SSHRoleExists(ctx context.Context, name string) (bool, error)
	ListTransitKeys(ctx context.Context) ([]openbao.TransitKey, error)
	CreateTransitKey(ctx context.Context, name, keyType string) error
	RotateTransitKey(ctx context.Context, name string) error
	ListSSHRoles(ctx context.Context) ([]openbao.SSHRole, error)
	CreateSSHRole(ctx context.Context, name, allowedUsers, ttl string) error
}

// Controller is one running controller.
type Controller struct {
	config  config.Controller
	store   *store.Store
	openbao OpenBao
	events  *events.Store
	agentOB protocol.OpenBao
	hub     *hub
	log     io.Writer
	now     func() time.Time
}

// Options configure a controller beyond its configuration document.
type Options struct {
	OpenBao OpenBao
	Log     io.Writer
}

// New opens the controller's durable state.
func New(configuration config.Controller, options Options) (*Controller, error) {
	if err := os.MkdirAll(configuration.StateDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	database, err := store.Open(filepath.Join(configuration.StateDirectory, "controller.db"))
	if err != nil {
		return nil, err
	}
	eventStore, err := events.Open(filepath.Join(configuration.StateDirectory, "events", "controller.events"), eventRetention)
	if err != nil {
		_ = database.Close()
		return nil, fmt.Errorf("open events: %w", err)
	}
	agentOpenBao := protocol.OpenBao{
		Address: configuration.OpenBao.Address, Namespace: configuration.OpenBao.Namespace,
		TransitMount: configuration.OpenBao.TransitMount, SSHMount: configuration.OpenBao.SSHMount,
	}
	if configuration.OpenBao.CAFile != "" {
		data, err := os.ReadFile(configuration.OpenBao.CAFile)
		if err != nil {
			_ = database.Close()
			_ = eventStore.Close()
			return nil, fmt.Errorf("read OpenBao CA: %w", err)
		}
		agentOpenBao.CAPEM = string(data)
	}
	manager := options.OpenBao
	if manager == nil {
		client, err := openbao.NewClient(openbao.Endpoint{
			Address: configuration.OpenBao.Address, CAFile: configuration.OpenBao.CAFile,
			Namespace: configuration.OpenBao.Namespace, Timeout: openBaoTimeout,
		})
		if err != nil {
			_ = database.Close()
			_ = eventStore.Close()
			return nil, err
		}
		secretFile := configuration.OpenBao.SecretIDFile
		manager = openbao.NewManager(client, openbao.Mounts{
			AppRole: configuration.OpenBao.AppRoleMount,
			Transit: configuration.OpenBao.TransitMount,
			SSH:     configuration.OpenBao.SSHMount,
		}, configuration.OpenBao.RoleID, func() (string, error) { return config.ReadSecretFile(secretFile) })
	}
	logWriter := options.Log
	if logWriter == nil {
		logWriter = io.Discard
	}
	controller := &Controller{
		config: configuration, store: database, openbao: manager, events: eventStore,
		agentOB: agentOpenBao, log: logWriter, now: func() time.Time { return time.Now().UTC() },
	}
	controller.hub = newHub(controller)
	return controller, nil
}

// Close releases durable state.
func (controller *Controller) Close() error {
	return errors.Join(controller.store.Close(), controller.events.Close())
}

// Store exposes durable state to the web interface.
func (controller *Controller) Store() *store.Store { return controller.store }

// Events exposes the controller event history.
func (controller *Controller) Events() *events.Store { return controller.events }

// Configuration returns the controller configuration.
func (controller *Controller) Configuration() config.Controller { return controller.config }

// Run logs in to OpenBao, maintains the controller token, and serves agents
// until ctx ends. The HTTP handler, when non-nil, is served on the
// configured HTTP address.
func (controller *Controller) Run(ctx context.Context, serveHTTP func(context.Context) error) error {
	signer, err := LoadOrCreateHostKey(controller.config.StateDirectory)
	if err != nil {
		return err
	}
	loginCtx, cancel := context.WithTimeout(ctx, openBaoTimeout)
	if err := controller.openbao.Login(loginCtx); err != nil {
		controller.logf("openbao login failed (%s); retrying in background", openbao.CategoryOf(err))
	}
	cancel()
	go controller.openbao.Maintain(ctx, loginRetryInterval)

	server, err := controller.newSSHServer(signer)
	if err != nil {
		return err
	}
	errorsChannel := make(chan error, 2)
	go func() { errorsChannel <- server.ListenAndServe() }()
	if serveHTTP != nil {
		go func() { errorsChannel <- serveHTTP(ctx) }()
	}
	controller.logf("controller serving agents on %s", controller.config.SSHListen)
	select {
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
		controller.hub.closeAll()
		return nil
	case err := <-errorsChannel:
		_ = server.Close()
		controller.hub.closeAll()
		return err
	}
}

func (controller *Controller) logf(format string, arguments ...any) {
	_, _ = fmt.Fprintf(controller.log, "wyrwood controller: "+format+"\n", arguments...)
}

func (controller *Controller) record(event events.Event) {
	if event.Time.IsZero() {
		event.Time = controller.now()
	}
	if err := controller.events.Append(event); err != nil {
		controller.logf("event not recorded")
	}
}

func openBaoError(err error) events.ErrorCode {
	switch openbao.CategoryOf(err) {
	case openbao.CategoryDenied:
		return events.ErrorOpenBaoDenied
	case openbao.CategoryTimeout:
		return events.ErrorOpenBaoTimeout
	case openbao.CategoryInvalid, openbao.CategoryNotFound:
		return events.ErrorPolicyDenied
	default:
		return events.ErrorOpenBaoUnavailable
	}
}

func outcomeFor(code events.ErrorCode) events.Outcome {
	switch code {
	case events.ErrorNone:
		return events.OutcomeOK
	case events.ErrorOpenBaoDenied, events.ErrorPolicyDenied, events.ErrorOperatorNotAllowed, events.ErrorRecreateNotAllowed:
		return events.OutcomeDenied
	case events.ErrorOpenBaoTimeout:
		return events.OutcomeTimeout
	default:
		return events.OutcomeFailed
	}
}
