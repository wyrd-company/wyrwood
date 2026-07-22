//go:build linux

// ---
// relationships:
//   implements: linux-per-user-agent-proxy
//   uses: control-interface
// ---

// Package daemon composes durable events, endpoint reconciliation, and the
// owner-authenticated local control server into one per-user process.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/wyrd-company/wyrwood/internal/agentconn"
	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/control"
	"github.com/wyrd-company/wyrwood/internal/endpoints"
	"github.com/wyrd-company/wyrwood/internal/events"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

const defaultEventRetention = 10_000

type Options struct {
	ConfigPath      string
	ControlPath     string
	EventPath       string
	EventRetention  int
	UID             uint32
	createStateRoot bool
}

func DefaultOptions() (Options, error) {
	configPath, err := config.DefaultPath()
	if err != nil {
		return Options{}, err
	}
	controlPath, err := DefaultControlPath()
	if err != nil {
		return Options{}, err
	}
	stateRoot, err := defaultStateRoot()
	if err != nil {
		return Options{}, err
	}
	return Options{
		ConfigPath: configPath, ControlPath: controlPath,
		EventPath: filepath.Join(stateRoot, "wyrwood", "events.bin"), EventRetention: defaultEventRetention,
		UID: uint32(os.Geteuid()), createStateRoot: true,
	}, nil
}

type Service struct {
	configPath string
	uid        uint32
	manager    *endpoints.Manager
	events     *events.Store
	control    *control.Server
	closeOnce  sync.Once
	closeErr   error
}

// Open restores configured consumer listeners without contacting the upstream
// agent, then binds the local control listener.
func Open(options Options) (*Service, error) {
	if options.UID != uint32(os.Geteuid()) {
		return nil, errors.New("daemon UID must equal the effective process UID")
	}
	if options.EventRetention == 0 {
		options.EventRetention = defaultEventRetention
	}
	if options.createStateRoot {
		if err := ensureStateRoot(filepath.Dir(filepath.Dir(options.EventPath))); err != nil {
			return nil, err
		}
	}
	store, err := events.Open(options.EventPath, options.EventRetention)
	if err != nil {
		return nil, fmt.Errorf("open operational events: %w", err)
	}
	configuration, err := loadConfiguration(options.ConfigPath, options.UID)
	if err != nil {
		_ = store.Close()
		return nil, errors.New("load daemon configuration")
	}
	manager, err := endpoints.Open(configuration, store)
	if err != nil {
		_ = store.Close()
		return nil, fmt.Errorf("restore consumer listeners: %w", err)
	}
	service := &Service{configPath: options.ConfigPath, uid: options.UID, manager: manager, events: store}
	server, err := control.Listen(options.ControlPath, options.UID, service)
	if err != nil {
		_ = manager.Close()
		_ = store.Close()
		return nil, fmt.Errorf("open control listener: %w", err)
	}
	service.control = server
	return service, nil
}

func Run(ctx context.Context, options Options) error {
	if ctx == nil {
		return errors.New("daemon context is required")
	}
	service, err := Open(options)
	if err != nil {
		return err
	}
	<-ctx.Done()
	return service.Close()
}

// Close stops control admission, then consumer listeners/pairs and retry loops,
// and finally closes durable events after endpoint shutdown can no longer emit.
func (service *Service) Close() error {
	service.closeOnce.Do(func() {
		service.closeErr = errors.Join(service.control.Close(), service.manager.Close(), service.events.Close())
	})
	return service.closeErr
}

func (service *Service) Apply() (control.ApplyResult, control.ErrorCode) {
	next, err := loadConfiguration(service.configPath, service.uid)
	if err != nil {
		return control.ApplyResult{}, control.ErrorApplyInvalid
	}
	result, err := service.manager.Apply(next)
	projection := control.ApplyResult{
		Committed: result.Committed, Degraded: result.Degraded,
		PendingCleanup: result.PendingCleanup, PendingPermissions: result.PendingPermissions,
	}
	if err != nil {
		if result.Committed {
			return projection, control.ErrorNone
		}
		return control.ApplyResult{}, control.ErrorApplyFailed
	}
	return projection, control.ErrorNone
}

func (service *Service) Keys() (control.KeysResult, control.ErrorCode) {
	snapshot := service.manager.Active()
	upstream, err := agentconn.New(snapshot.Upstream(), snapshot.Timeouts())
	if err != nil {
		return control.KeysResult{}, control.ErrorInternal
	}
	defer upstream.Close()
	listed, err := upstream.List()
	if err != nil {
		return control.KeysResult{}, control.ErrorUpstreamUnavailable
	}
	if len(listed) > control.MaximumProjectedKeys {
		return control.KeysResult{}, control.ErrorResourceLimit
	}
	keys := make([]control.Key, 0, len(listed))
	for _, key := range listed {
		if key == nil {
			return control.KeysResult{}, control.ErrorInternal
		}
		publicKey, err := ssh.ParsePublicKey(key.Marshal())
		if err != nil {
			return control.KeysResult{}, control.ErrorInternal
		}
		keys = append(keys, control.Key{Fingerprint: ssh.FingerprintSHA256(publicKey), Display: boundedDisplay(key.Comment)})
	}
	return control.KeysResult{Keys: keys}, control.ErrorNone
}

func (service *Service) Status() (control.StatusResult, control.ErrorCode) {
	health := service.manager.Health()
	daemonHealth := control.HealthHealthy
	if health.Degraded {
		daemonHealth = control.HealthDegraded
	}
	upstreamHealth := control.HealthUnavailable
	connection, err := net.DialTimeout("unix", service.manager.Active().Upstream(), time.Second)
	if err == nil {
		upstreamHealth = control.HealthHealthy
		_ = connection.Close()
	}
	statuses, truncated := service.manager.ConsumerStatuses(control.MaximumProjectedConsumers)
	consumers := make([]control.ConsumerStatus, 0, len(statuses))
	for _, status := range statuses {
		listener := control.HealthHealthy
		if !status.Listening || health.ListenerError {
			listener = control.HealthDegraded
		}
		consumers = append(consumers, control.ConsumerStatus{
			ID: status.ID, Name: status.Name, Listener: listener, ActiveConnections: status.ActiveConnections,
		})
	}
	return control.StatusResult{Daemon: daemonHealth, Upstream: upstreamHealth, Consumers: consumers, Truncated: truncated}, control.ErrorNone
}

func (service *Service) Events(limit int) (control.EventsResult, control.ErrorCode) {
	if limit < 1 || limit > control.MaximumEventLimit {
		return control.EventsResult{}, control.ErrorBadRequest
	}
	recent := service.events.Recent(limit)
	result := make([]control.Event, 0, len(recent))
	for _, event := range recent {
		var fingerprint *string
		if event.Fingerprint != nil {
			value := string(*event.Fingerprint)
			fingerprint = &value
		}
		result = append(result, control.Event{
			Timestamp: event.Timestamp, ConsumerID: string(event.ConsumerID), Operation: string(event.Operation),
			Fingerprint: fingerprint, Outcome: string(event.Outcome), LatencyNS: int64(event.Latency), ErrorCode: string(event.ErrorCode),
		})
	}
	return control.EventsResult{Events: result}, control.ErrorNone
}

func boundedDisplay(value string) string {
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= control.MaximumDisplayBytes {
		return value
	}
	value = value[:control.MaximumDisplayBytes]
	for !utf8.ValidString(value) {
		value = value[:len(value)-1]
	}
	return value
}

func ensureStateRoot(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("state root must be canonical and absolute")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return errors.New("create state root")
	}
	return nil
}

func loadConfiguration(path string, uid uint32) (config.Config, error) {
	return loadConfigurationWithHook(path, uid, nil)
}

func loadConfigurationWithHook(path string, uid uint32, afterFileOpen func()) (config.Config, error) {
	if strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Dir(path) == string(filepath.Separator) {
		return config.Config{}, errors.New("configuration path must be canonical, absolute, and use a dedicated directory")
	}
	directoryDescriptor, err := unix.Open(
		filepath.Dir(path),
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return config.Config{}, errors.New("open configuration directory")
	}
	defer unix.Close(directoryDescriptor)
	var directoryStatus unix.Stat_t
	if err := unix.Fstat(directoryDescriptor, &directoryStatus); err != nil ||
		directoryStatus.Uid != uid || directoryStatus.Mode&unix.S_IFMT != unix.S_IFDIR || directoryStatus.Mode&0o7777 != 0o700 {
		return config.Config{}, errors.New("configuration directory must be owner-only")
	}

	fileDescriptor, err := unix.Openat(
		directoryDescriptor,
		filepath.Base(path),
		unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC,
		0,
	)
	if err != nil {
		return config.Config{}, errors.New("open configuration file")
	}
	file := os.NewFile(uintptr(fileDescriptor), filepath.Base(path))
	if file == nil {
		_ = unix.Close(fileDescriptor)
		return config.Config{}, errors.New("own configuration file descriptor")
	}
	defer file.Close()
	var fileStatus unix.Stat_t
	if err := unix.Fstat(fileDescriptor, &fileStatus); err != nil ||
		fileStatus.Uid != uid || fileStatus.Mode&unix.S_IFMT != unix.S_IFREG || fileStatus.Mode&0o7777 != 0o600 {
		return config.Config{}, errors.New("configuration file must be owner-only and regular")
	}
	if afterFileOpen != nil {
		afterFileOpen()
	}
	data, err := io.ReadAll(io.LimitReader(file, config.MaximumDocumentBytes+1))
	if err != nil {
		return config.Config{}, errors.New("read configuration file")
	}
	return config.Parse(data)
}
