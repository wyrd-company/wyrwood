// ---
// relationships:
//   verifies:
//     - agent
//     - agent-controller-protocol
// ---

package agent

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/engine/enginetest"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/openbao"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

func onlyStatus(t *testing.T, instance *Agent) protocol.BindingStatus {
	t.Helper()
	statuses := instance.bindingStatuses()
	if len(statuses) != 1 {
		t.Fatalf("statuses = %#v", statuses)
	}
	return statuses[0]
}

func TestPreparedBindingReportsItsDirectoryWithNoContainerOrToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance := newRecreateAgent(t, enginetest.New())
	group := uint32(os.Getgid())
	settings := policy.DefaultSettings()
	settings.AccessGroup = &group
	bound := preparedBinding(appKey(), settings)
	instance.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", bound))

	status := onlyStatus(t, instance)
	if status.Binding != bound.Binding || status.Assignment != bound.Assignment || status.Token != protocol.TokenNone || status.Outcome != "" {
		t.Fatalf("status = %#v", status)
	}
	if len(status.Consumers) != 1 {
		t.Fatalf("consumers = %#v", status.Consumers)
	}
	consumer := status.Consumers[0]
	if consumer.Directory != instance.root.DirectoryPath("app") || consumer.ContainerID != "" || consumer.Failed != "" ||
		consumer.AccessGroup == nil || *consumer.AccessGroup != group || !slices.Equal(consumer.Sockets, protocol.Sockets) {
		t.Fatalf("consumer = %#v", consumer)
	}
}

func TestDirectoryFailureIsReportedWithItsCause(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance := newRecreateAgent(t, enginetest.New())
	if err := os.WriteFile(instance.root.DirectoryPath("app"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	group := uint32(os.Getgid())
	settings := policy.DefaultSettings()
	settings.AccessGroup = &group
	instance.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", preparedBinding(appKey(), settings)))

	consumer := onlyStatus(t, instance).Consumers[0]
	if consumer.Directory != instance.root.DirectoryPath("app") || consumer.Failed != protocol.FailedConsumerDirectory || len(consumer.Sockets) != 0 || consumer.AccessGroup != nil {
		t.Fatalf("occupied directory = %#v", consumer)
	}
	instance.canAssign = func(uint32) bool { return false }
	if got := onlyStatus(t, instance).Consumers[0].Failed; got != protocol.FailedAccessGroup {
		t.Fatalf("unassignable group = %q", got)
	}
}

func TestGroupNotAppliedIsReported(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance := newRecreateAgent(t, enginetest.New())
	group := uint32(os.Getgid())
	settings := policy.DefaultSettings()
	settings.AccessGroup = &group
	instance.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", preparedBinding(appKey(), settings)))
	// What a failed SetGroup leaves: the directory keeps its earlier group.
	instance.mu.Lock()
	instance.consumers["app"].group = nil
	instance.mu.Unlock()

	consumer := onlyStatus(t, instance).Consumers[0]
	if consumer.Failed != protocol.FailedAccessGroup || consumer.AccessGroup != nil {
		t.Fatalf("consumer = %#v", consumer)
	}
}

func TestMissingSocketFailsTheConsumer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance := newRecreateAgent(t, enginetest.New())
	instance.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", preparedBinding(appKey(), policy.DefaultSettings())))
	instance.mu.Lock()
	instance.consumers["app"].sockets = []protocol.Socket{protocol.SocketVault}
	instance.mu.Unlock()

	consumer := onlyStatus(t, instance).Consumers[0]
	if consumer.Failed != protocol.FailedConsumerDirectory || !slices.Equal(consumer.Sockets, []protocol.Socket{protocol.SocketVault}) {
		t.Fatalf("consumer = %#v", consumer)
	}
}

// Readiness reads this status, so after removal it must not keep the removed
// container's result, and a replacement must carry its own identifier.
func TestStatusFollowsTheContainerThroughRemovalAndReplacement(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	openBao := newFakeOpenBao(t)
	engineFake := enginetest.New()
	instance := newRecreateAgent(t, engineFake)
	instance.creds.retryDelay = time.Hour
	bound := preparedBinding(appKey(), policy.DefaultSettings())
	instance.applyPolicySet(ctx, preparedSet(openBao.server.URL, bound))
	app := runningApp(engineFake)
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	status := onlyStatus(t, instance)
	if status.Consumers[0].ContainerID != app.ID || status.Outcome == "" || status.Token != protocol.TokenNone {
		t.Fatalf("observed = %#v", status)
	}
	deliverToken(ctx, t, instance, bound, "role-a")
	if got := onlyStatus(t, instance).Token; got != protocol.TokenValid {
		t.Fatalf("token = %q", got)
	}

	engineFake.Destroy(app.ID)
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	status = onlyStatus(t, instance)
	if status.Consumers[0].ContainerID != "" || status.Outcome != "" || len(status.FailedItems) != 0 || status.Token != protocol.TokenNone {
		t.Fatalf("after removal = %#v", status)
	}
	if !slices.Equal(status.Consumers[0].Sockets, protocol.Sockets) {
		t.Fatalf("sockets after removal = %#v", status.Consumers[0].Sockets)
	}

	replacement := runningApp(engineFake)
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if got := onlyStatus(t, instance).Consumers[0].ContainerID; got != replacement.ID || got == app.ID {
		t.Fatalf("replacement id = %q", got)
	}
}

// A recreate removes the container first; its binding stays reported as recreating.
func TestRecreatingBindingKeepsItsOutcomeThroughTheGap(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance := newRecreateAgent(t, enginetest.New())
	bound := preparedBinding(appKey(), policy.DefaultSettings())
	instance.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", bound))
	instance.mu.Lock()
	instance.recreating["app"] = true
	instance.results[bound.Binding] = protocol.ContractResult{Binding: bound.Binding, Outcome: protocol.OutcomeRecreating}
	instance.mu.Unlock()
	if got := onlyStatus(t, instance).Outcome; got != protocol.OutcomeRecreating {
		t.Fatalf("outcome = %q", got)
	}
}

func TestLastErrorHoldsUntilASuccessAndIgnoresRevocation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance := newRecreateAgent(t, enginetest.New())
	bound := preparedBinding(appKey(), policy.DefaultSettings())
	instance.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", bound))

	denied := &openbao.Error{Category: openbao.CategoryDenied}
	instance.creds.recordOutcome(events.OperationLogin, bound.Binding, time.Now(), denied)
	if got := onlyStatus(t, instance).LastError; got != protocol.CredentialDenied {
		t.Fatalf("after a denied login = %q", got)
	}
	instance.creds.recordOutcome(events.OperationRevoke, bound.Binding, time.Now(), nil)
	if got := onlyStatus(t, instance).LastError; got != protocol.CredentialDenied {
		t.Fatalf("after a revocation = %q", got)
	}
	instance.creds.recordOutcome(events.OperationRenew, bound.Binding, time.Now(), errors.New("unavailable"))
	if got := onlyStatus(t, instance).LastError; got != protocol.CredentialUnavailable {
		t.Fatalf("after a failed renewal = %q", got)
	}
	instance.creds.recordOutcome(events.OperationLogin, bound.Binding, time.Now(), nil)
	if got := onlyStatus(t, instance).LastError; got != "" {
		t.Fatalf("after a login = %q", got)
	}
	instance.creds.recordOutcome(events.OperationLogin, bound.Binding, time.Now(), denied)
	instance.creds.retire(bound.Binding)
	if got := onlyStatus(t, instance).LastError; got != "" {
		t.Fatalf("after retirement = %q", got)
	}
}

func TestEveryCredentialCodeEncodes(t *testing.T) {
	for _, category := range []openbao.Category{openbao.CategoryDenied, openbao.CategoryTimeout, openbao.CategoryInvalid, openbao.CategoryNotFound, openbao.CategoryUnavailable} {
		code := openBaoCode(&openbao.Error{Category: category})
		status := protocol.BindingStatus{Binding: "bnd-1", Assignment: "assignment", Token: protocol.TokenNone, LastError: credentialError(code)}
		if err := status.Validate(); err != nil {
			t.Fatalf("category %v: %v", category, err)
		}
	}
}

func receiveStatus(t *testing.T, session *controllerSession) protocol.BindingStatus {
	t.Helper()
	select {
	case message := <-session.queue:
		status, ok := message.(protocol.BindingStatus)
		if !ok {
			t.Fatalf("message = %#v", message)
		}
		return status
	case <-time.After(5 * time.Second):
		t.Fatal("no status sent")
	}
	return protocol.BindingStatus{}
}

func TestReporterSendsAtSessionStartAndOnlyOnChange(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance := newRecreateAgent(t, enginetest.New())
	bound := preparedBinding(appKey(), policy.DefaultSettings())
	instance.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", bound))

	session := newControllerSession(nil, nil)
	finished := make(chan struct{})
	go func() { defer close(finished); instance.reportBindingStatuses(session) }()
	if first := receiveStatus(t, session); first.Binding != bound.Binding || first.Token != protocol.TokenNone {
		t.Fatalf("first status = %#v", first)
	}
	// Let the wake from applying the set drain, so that this change needs its own.
	time.Sleep(50 * time.Millisecond)
	instance.creds.recordOutcome(events.OperationLogin, bound.Binding, time.Now(), &openbao.Error{Category: openbao.CategoryDenied})
	if changed := receiveStatus(t, session); changed.LastError != protocol.CredentialDenied {
		t.Fatalf("changed status = %#v", changed)
	}
	instance.wakeStatus()
	select {
	case message := <-session.queue:
		t.Fatalf("repeated status = %#v", message)
	case <-time.After(100 * time.Millisecond):
	}
	close(session.done)
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("reporter outlived its session")
	}
}

// Each step here changes the status by a path other than an explicit wake.
func TestReporterFollowsContainerAndToken(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	openBao := newFakeOpenBao(t)
	engineFake := enginetest.New()
	instance := newRecreateAgent(t, engineFake)
	instance.creds.retryDelay = time.Hour
	bound := preparedBinding(appKey(), policy.DefaultSettings())
	session := newControllerSession(nil, nil)
	finished := make(chan struct{})
	go func() { defer close(finished); instance.reportBindingStatuses(session) }()
	defer func() { close(session.done); <-finished }()
	// The reporter has nothing to send until a set arrives, and then applying it
	// is the only wake.
	time.Sleep(50 * time.Millisecond)
	instance.applyPolicySet(ctx, preparedSet(openBao.server.URL, bound))
	await := func(what string, wanted func(protocol.BindingStatus) bool) {
		t.Helper()
		deadline := time.After(10 * time.Second)
		for {
			select {
			case message := <-session.queue:
				if status, ok := message.(protocol.BindingStatus); ok && wanted(status) {
					return
				}
			case <-deadline:
				t.Fatalf("no status with %s", what)
			}
		}
	}
	await("a prepared consumer", func(status protocol.BindingStatus) bool {
		return len(status.Consumers) == 1 && status.Consumers[0].ContainerID == ""
	})
	time.Sleep(50 * time.Millisecond)

	app := runningApp(engineFake)
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	await("the observed container", func(status protocol.BindingStatus) bool {
		return status.Consumers[0].ContainerID == app.ID && status.Outcome != ""
	})
	time.Sleep(50 * time.Millisecond)

	deliverToken(ctx, t, instance, bound, "role-a")
	await("a valid token", func(status protocol.BindingStatus) bool { return status.Token == protocol.TokenValid })
	time.Sleep(50 * time.Millisecond)

	// The revoke's own outcome could wake the reporter; invalidating must not rely on it.
	instance.creds.invalidate(bound.Binding)
	await("no token", func(status protocol.BindingStatus) bool { return status.Token == protocol.TokenNone })
	time.Sleep(50 * time.Millisecond)

	instance.mu.Lock()
	instance.reportLocked(protocol.ContractResult{Binding: bound.Binding, Outcome: protocol.OutcomeRecreating})
	instance.mu.Unlock()
	await("the new result", func(status protocol.BindingStatus) bool { return status.Outcome == protocol.OutcomeRecreating })
}

// A second container of a binding changes neither its result nor its token, so
// applying the observation is what wakes the reporter.
func TestReporterSendsANewContainerOfABinding(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	engineFake := enginetest.New()
	instance := newRecreateAgent(t, engineFake)
	instance.creds.retryDelay = time.Hour
	worker := func(name string) engine.Container {
		container := engine.Container{Name: "/" + name}
		container.State.Status = "running"
		container.Config.Labels = map[string]string{"com.docker.compose.project": "shop", "com.docker.compose.service": "app"}
		engineFake.Add(container)
		added, _ := engineFake.ByName(name)
		return added
	}
	bound := preparedBinding(protocol.Key{Kind: protocol.KeyCompose, Value: "shop/app"}, policy.DefaultSettings())
	instance.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", bound))
	worker("app-1")
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	session := newControllerSession(nil, nil)
	finished := make(chan struct{})
	go func() { defer close(finished); instance.reportBindingStatuses(session) }()
	defer func() { close(session.done); <-finished }()
	if first := receiveStatus(t, session); len(first.Consumers) != 1 {
		t.Fatalf("first status = %#v", first)
	}
	time.Sleep(100 * time.Millisecond)
	second := worker("app-2")
	if err := instance.fullReconcile(ctx); err != nil {
		t.Fatal(err)
	}
	status := receiveStatus(t, session)
	if len(status.Consumers) != 2 || !slices.ContainsFunc(status.Consumers, func(consumer protocol.ConsumerStatus) bool { return consumer.ContainerID == second.ID }) {
		t.Fatalf("status = %#v", status)
	}
}

// A result kept for a binding on another key says nothing once it governs no
// container: the controller has yet to withdraw it, and its result is stale.
func TestResultIsNotReportedWithNoContainer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance := newRecreateAgent(t, enginetest.New())
	bound := preparedBinding(protocol.Key{Kind: protocol.KeyCompose, Value: "sample/worker"}, policy.DefaultSettings())
	instance.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", bound))
	instance.mu.Lock()
	instance.results[bound.Binding] = protocol.ContractResult{Binding: bound.Binding, Outcome: protocol.OutcomeConforming}
	instance.mu.Unlock()
	status := onlyStatus(t, instance)
	if status.Outcome != "" || len(status.Consumers) != 0 {
		t.Fatalf("status = %#v", status)
	}
}

// watchTokenEnd reports whether a wake arrived after a held token left.
func watchTokenEnd(manager *credentials, binding string) *atomic.Bool {
	var seen, ended atomic.Bool
	manager.changed = func() {
		if _, held := manager.holding()[binding]; held {
			seen.Store(true)
		} else if seen.Load() {
			ended.Store(true)
		}
	}
	return &ended
}

// The login's outcome wakes the reporter before the token is held, so holding
// it needs a wake of its own.
func TestDeliveredTokenWakesTheReporterWhileHeld(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeOpenBao(t)
	manager := newTestCredentials(t, fake, func(string) {})
	var wokeHolding atomic.Bool
	manager.changed = func() {
		if _, held := manager.holding()["bnd-1"]; held {
			wokeHolding.Store(true)
		}
	}
	manager.deliver(ctx, credential("bnd-1", "role-1"), manager.begin("bnd-1"), []string{"wyrwood-example"}, true)
	if !wokeHolding.Load() {
		t.Fatal("no wake with the token held")
	}
}

func TestRenewalThatFindsTheTokenExpiredWakesTheReporter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeOpenBao(t)
	fake.ttl["role-1"] = 1
	fake.failRenew = true
	manager := newTestCredentials(t, fake, func(string) {})
	manager.retryDelay = time.Hour
	ended := watchTokenEnd(manager, "bnd-1")
	manager.deliver(ctx, credential("bnd-1", "role-1"), manager.begin("bnd-1"), []string{"wyrwood-example"}, true)
	eventually(t, "a wake after the token expired", ended.Load)
}

func TestExpiryWithoutRenewalWakesTheReporter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fake := newFakeOpenBao(t)
	fake.ttl["role-1"] = 1
	manager := newTestCredentials(t, fake, func(string) {})
	manager.retryDelay = time.Hour
	ended := watchTokenEnd(manager, "bnd-1")
	manager.deliver(ctx, credential("bnd-1", "role-1"), manager.begin("bnd-1"), []string{"wyrwood-example"}, false)
	eventually(t, "a wake after the token expired", ended.Load)
}

// A new session's reporter resends what the last one sent: the controller keeps
// status for one session only.
func TestReporterResendsInANewSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	instance := newRecreateAgent(t, enginetest.New())
	instance.applyPolicySet(ctx, preparedSet("http://127.0.0.1:1", preparedBinding(appKey(), policy.DefaultSettings())))
	for range 2 {
		session := newControllerSession(nil, nil)
		finished := make(chan struct{})
		go func() { defer close(finished); instance.reportBindingStatuses(session) }()
		receiveStatus(t, session)
		close(session.done)
		<-finished
	}
}
