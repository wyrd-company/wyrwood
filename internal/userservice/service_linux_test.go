//go:build linux

// ---
// relationships:
//   verifies: linux-user-service
// ---

package userservice

import (
	"errors"
	"io"
	"reflect"
	"testing"
)

type fakeStore struct {
	installed      bool
	changed        bool
	pendingRestart bool
	err            error
	installErr     error
	calls          []string
}

func (store *fakeStore) inspect(string, uint32) (bool, error) {
	store.calls = append(store.calls, "inspect")
	return store.installed, store.err
}
func (store *fakeStore) install(string, []byte, uint32) (bool, error) {
	store.calls = append(store.calls, "install")
	store.installed = true
	if store.changed {
		store.pendingRestart = true
	}
	return store.changed, store.installErr
}
func (store *fakeStore) remove(string, uint32) (bool, error) {
	store.calls = append(store.calls, "remove")
	if store.err != nil {
		return false, store.err
	}
	store.installed = false
	store.pendingRestart = false
	return true, nil
}
func (store *fakeStore) pending(string, uint32) (bool, error) {
	store.calls = append(store.calls, "pending")
	return store.pendingRestart, store.err
}
func (store *fakeStore) clearPending(string, uint32) error {
	store.calls = append(store.calls, "clear-pending")
	store.pendingRestart = false
	return store.err
}

type fakeController struct {
	enabled       bool
	state         State
	failAt        string
	preventEnable bool
	calls         []string
}

func (control *fakeController) operation(name string) error {
	control.calls = append(control.calls, name)
	if control.failAt == name {
		return ErrController
	}
	return nil
}
func (control *fakeController) reload() error { return control.operation("reload") }
func (control *fakeController) enable(string) error {
	err := control.operation("enable")
	if err == nil && !control.preventEnable {
		control.enabled = true
	}
	return err
}
func (control *fakeController) tryRestart() error { return control.operation("try-restart") }
func (control *fakeController) disableNow() error {
	control.enabled, control.state = false, StateInactive
	return control.operation("disable-now")
}
func (control *fakeController) start() error {
	control.state = StateActive
	return control.operation("start")
}
func (control *fakeController) stop() error {
	control.state = StateInactive
	return control.operation("stop")
}
func (control *fakeController) status() (bool, State, error) {
	if err := control.operation("status"); err != nil {
		return false, "", err
	}
	return control.enabled, control.state, nil
}

func TestManagerInstallSequencesReloadEnableAndSafeRestart(t *testing.T) {
	for _, test := range []struct {
		name       string
		changed    bool
		wantCalls  []string
		initialRun State
	}{
		{name: "new bytes", changed: true, initialRun: StateActive, wantCalls: []string{"reload", "enable", "try-restart", "status"}},
		{name: "same bytes", changed: false, initialRun: StateInactive, wantCalls: []string{"reload", "enable", "status"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &fakeStore{changed: test.changed}
			control := &fakeController{state: test.initialRun}
			service := testManager(store, control)
			result, err := service.manage(ActionInstall)
			if err != nil || !result.Installed || !result.Enabled || result.State != test.initialRun {
				t.Fatalf("install = (%#v, %v)", result, err)
			}
			if !reflect.DeepEqual(control.calls, test.wantCalls) {
				t.Fatalf("controller calls = %v, want %v", control.calls, test.wantCalls)
			}
		})
	}
}

func TestManagerRemoveDisablesBeforeUnlinkAndReloads(t *testing.T) {
	store := &fakeStore{installed: true}
	control := &fakeController{enabled: true, state: StateActive}
	result, err := testManager(store, control).manage(ActionRemove)
	if err != nil || result.Installed || result.Enabled || result.State != StateNotInstalled {
		t.Fatalf("remove = (%#v, %v)", result, err)
	}
	if !reflect.DeepEqual(control.calls, []string{"disable-now", "reload"}) || !reflect.DeepEqual(store.calls, []string{"inspect", "remove"}) {
		t.Fatalf("calls = controller %v, store %v", control.calls, store.calls)
	}

	control.calls = nil
	store.calls = nil
	result, err = testManager(store, control).manage(ActionRemove)
	if err != nil || result.State != StateNotInstalled || !reflect.DeepEqual(control.calls, []string{"reload"}) || !reflect.DeepEqual(store.calls, []string{"inspect", "remove"}) {
		t.Fatalf("idempotent remove = (%#v, %v), calls %v %v", result, err, control.calls, store.calls)
	}
}

func TestManagerRetriesReloadAfterInstallCommittedBeforeFailure(t *testing.T) {
	store := &fakeStore{changed: true}
	control := &fakeController{state: StateInactive, failAt: "reload"}
	service := testManager(store, control)
	if _, err := service.manage(ActionInstall); !errors.Is(err, ErrController) {
		t.Fatalf("first install error = %v", err)
	}
	store.changed = false
	control.failAt = ""
	control.calls = nil
	result, err := service.manage(ActionInstall)
	if err != nil || !result.Installed || !result.Enabled ||
		!reflect.DeepEqual(control.calls, []string{"reload", "enable", "try-restart", "status"}) {
		t.Fatalf("retry = (%#v, %v), calls %v", result, err, control.calls)
	}
}

func TestManagerRetriesPendingRestartAfterPostRenameDurabilityFailure(t *testing.T) {
	store := &fakeStore{changed: true, installErr: &DurabilityError{Err: errors.New("fixture sync failure")}}
	control := &fakeController{state: StateActive}
	service := testManager(store, control)
	if _, err := service.manage(ActionInstall); err == nil || !store.installed || !store.pendingRestart || len(control.calls) != 0 {
		t.Fatalf("first install = %v, installed %t, pending %t, calls %v", err, store.installed, store.pendingRestart, control.calls)
	}
	store.changed = false
	store.installErr = nil
	result, err := service.manage(ActionInstall)
	if err != nil || result.State != StateActive || store.pendingRestart ||
		!reflect.DeepEqual(control.calls, []string{"reload", "enable", "try-restart", "status"}) {
		t.Fatalf("retry = (%#v, %v), pending %t, calls %v", result, err, store.pendingRestart, control.calls)
	}
}

func TestManagerRetriesPendingRestartAfterControllerFailure(t *testing.T) {
	store := &fakeStore{changed: true}
	control := &fakeController{state: StateActive, failAt: "try-restart"}
	service := testManager(store, control)
	if _, err := service.manage(ActionInstall); !errors.Is(err, ErrController) || !store.pendingRestart {
		t.Fatalf("first install = %v, pending %t", err, store.pendingRestart)
	}
	store.changed = false
	control.failAt = ""
	control.calls = nil
	result, err := service.manage(ActionInstall)
	if err != nil || result.State != StateActive || store.pendingRestart ||
		!reflect.DeepEqual(control.calls, []string{"reload", "enable", "try-restart", "status"}) {
		t.Fatalf("retry = (%#v, %v), pending %t, calls %v", result, err, store.pendingRestart, control.calls)
	}
}

func TestManagerRetriesReloadAfterRemoveUnlinkedBeforeFailure(t *testing.T) {
	store := &fakeStore{installed: true}
	control := &fakeController{enabled: true, state: StateActive, failAt: "reload"}
	service := testManager(store, control)
	if _, err := service.manage(ActionRemove); !errors.Is(err, ErrController) || store.installed {
		t.Fatalf("first remove = %v, installed %t", err, store.installed)
	}
	control.failAt = ""
	control.calls = nil
	result, err := service.manage(ActionRemove)
	if err != nil || result.State != StateNotInstalled || !reflect.DeepEqual(control.calls, []string{"reload"}) {
		t.Fatalf("retry = (%#v, %v), calls %v", result, err, control.calls)
	}
}

func TestManagerStartStopAndStatusAreVerified(t *testing.T) {
	store := &fakeStore{installed: true}
	control := &fakeController{enabled: true, state: StateInactive}
	service := testManager(store, control)
	started, err := service.manage(ActionStart)
	if err != nil || started.State != StateActive {
		t.Fatalf("start = (%#v, %v)", started, err)
	}
	stopped, err := service.manage(ActionStop)
	if err != nil || stopped.State != StateInactive {
		t.Fatalf("stop = (%#v, %v)", stopped, err)
	}
	status, err := service.manage(ActionStatus)
	if err != nil || status.State != StateInactive || !status.Installed || !status.Enabled {
		t.Fatalf("status = (%#v, %v)", status, err)
	}
	if !reflect.DeepEqual(control.calls, []string{"start", "status", "stop", "status", "status"}) {
		t.Fatalf("controller calls = %v", control.calls)
	}
}

func TestManagerDoesNotReportPartialOperationsAsSuccess(t *testing.T) {
	for _, stage := range []string{"reload", "enable", "try-restart", "status"} {
		t.Run("install "+stage, func(t *testing.T) {
			store := &fakeStore{changed: true}
			control := &fakeController{state: StateInactive, failAt: stage}
			if _, err := testManager(store, control).manage(ActionInstall); !errors.Is(err, ErrController) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	store := &fakeStore{installed: true}
	control := &fakeController{enabled: true, state: StateActive, failAt: "disable-now"}
	if _, err := testManager(store, control).manage(ActionRemove); !errors.Is(err, ErrController) || reflect.DeepEqual(store.calls, []string{"inspect", "remove"}) {
		t.Fatalf("remove error = %v, store calls %v", err, store.calls)
	}
}

func TestManagerDoesNotReportInstallSuccessUntilLoginEnablementIsVisible(t *testing.T) {
	store := &fakeStore{changed: true}
	control := &fakeController{state: StateInactive, preventEnable: true}
	if _, err := testManager(store, control).manage(ActionInstall); !errors.Is(err, ErrController) {
		t.Fatalf("install error = %v", err)
	}
}

func TestManagerRequiresInstallationForStartAndStop(t *testing.T) {
	for _, action := range []Action{ActionStart, ActionStop} {
		if _, err := testManager(&fakeStore{}, &fakeController{}).manage(action); !errors.Is(err, ErrNotInstalled) {
			t.Fatalf("%s error = %v", action, err)
		}
	}
}

func testManager(store unitStore, control controller) manager {
	return manager{
		paths: func() (paths, error) {
			return paths{unit: "/tmp/sample/systemd/user/" + UnitName, executable: "/opt/sample/bin/tool", environment: fixtureEnvironment()}, nil
		},
		store: store, controller: control, locker: noopOperationLocker{}, uid: 1000,
	}
}

type noopOperationLocker struct{}

func (noopOperationLocker) lock(string, uint32) (io.Closer, error) { return noopCloser{}, nil }

type noopCloser struct{}

func (noopCloser) Close() error { return nil }
