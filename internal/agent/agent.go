// ---
// relationships:
//   implements: agent
//   uses:
//     - container-contract
//     - agent-controller-protocol
//     - operational-events
// ---

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/wyrd-company/wyrwood/internal/binding"
	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/consumer"
	"github.com/wyrd-company/wyrwood/internal/contract"
	"github.com/wyrd-company/wyrwood/internal/engine"
	"github.com/wyrd-company/wyrwood/internal/events"
	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

const (
	eventRetention     = 10_000
	reconcileInterval  = 5 * time.Minute
	recreateRetryDelay = 5 * time.Second
)

// Version is the agent version reported to the controller.
var Version = "dev"

// Options configure an agent.
type Options struct {
	Config    config.Agent
	Paths     Paths
	Engine    engine.Engine
	Endpoints binding.Endpoints
	Log       io.Writer
	// CanAssign reports whether the agent user can assign a group; it
	// defaults to the process's group membership.
	CanAssign func(uint32) bool
	// Hostname overrides the SSH username presented to the controller.
	Hostname string
}

// Agent is one running agent.
type Agent struct {
	config    config.Agent
	paths     Paths
	engine    engine.Engine
	endpoints binding.Endpoints
	log       io.Writer
	canAssign func(uint32) bool
	hostname  string
	events    *events.Store
	root      *consumer.Root
	creds     *credentials
	reconcile chan string

	mu         sync.Mutex
	containers map[string]engine.Container
	set        protocol.PolicySet
	setLoaded  bool
	known      map[string]bool
	consumers  map[string]*consumerState
	results    map[string]protocol.ContractResult
	recreating map[string]bool
	pending    map[string]contract.CreateRequest
	session    *controllerSession
	connected  bool
	lastReport time.Time
}

type consumerState struct {
	directory *consumer.Directory
	binding   string
	group     *uint32
	listeners []net.Listener
}

type policyCache struct {
	Version  int                `json:"version"`
	Set      protocol.PolicySet `json:"policy-set"`
	Bindings []string           `json:"known-bindings"`
}

// New prepares an agent: it opens the event store and the consumer root.
func New(options Options) (*Agent, error) {
	if options.Log == nil {
		options.Log = io.Discard
	}
	if options.CanAssign == nil {
		options.CanAssign = consumer.CanAssign
	}
	if options.Hostname == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, errors.New("hostname unavailable")
		}
		options.Hostname = hostname
	}
	eventStore, err := events.Open(options.Paths.Events(), eventRetention)
	if err != nil {
		return nil, fmt.Errorf("open events: %w", err)
	}
	root, err := consumer.OpenRoot(options.Config.ConsumerRoot)
	if err != nil {
		_ = eventStore.Close()
		return nil, err
	}
	agent := &Agent{
		config: options.Config, paths: options.Paths, engine: options.Engine, endpoints: options.Endpoints,
		log: options.Log, canAssign: options.CanAssign, hostname: options.Hostname, events: eventStore, root: root,
		reconcile:  make(chan string, 256),
		containers: map[string]engine.Container{}, known: map[string]bool{}, consumers: map[string]*consumerState{},
		results: map[string]protocol.ContractResult{}, recreating: map[string]bool{}, pending: map[string]contract.CreateRequest{},
	}
	agent.creds = newCredentials(options.Config.OpenBaoTimeout, agent.requestCredential, agent.record, agent.bindingKey)
	agent.creds.report = agent.reportAccessor
	return agent, nil
}

// Run serves until ctx ends. Consumer directories and sockets are restored
// from the policy cache before the controller is contacted.
func (agent *Agent) Run(ctx context.Context) error {
	defer agent.shutdown()
	agent.loadCache()
	control, err := agent.listenControl()
	if err != nil {
		return err
	}
	defer control.Close()
	if err := agent.fullReconcile(ctx); err != nil {
		agent.logf("engine unavailable at start")
	}
	go agent.watchEngine(ctx)
	go agent.runController(ctx)
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			_ = agent.fullReconcile(ctx)
		case id := <-agent.reconcile:
			agent.reconcileContainer(ctx, id)
		}
	}
}

func (agent *Agent) shutdown() {
	agent.mu.Lock()
	for _, state := range agent.consumers {
		for _, listener := range state.listeners {
			_ = listener.Close()
		}
		_ = state.directory.Close()
	}
	agent.consumers = map[string]*consumerState{}
	agent.mu.Unlock()
	agent.creds.stopAll()
	_ = agent.events.Close()
}

func (agent *Agent) logf(format string, arguments ...any) {
	_, _ = fmt.Fprintf(agent.log, "wyrwood agent: "+format+"\n", arguments...)
}

func (agent *Agent) record(event events.Event) {
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	if err := agent.events.Append(event); err != nil {
		agent.logf("event not recorded")
	}
}

// loadCache restores the last policy set so contracts and sockets survive a
// restart without the controller.
func (agent *Agent) loadCache() {
	data, err := os.ReadFile(agent.paths.PolicyCache())
	if err != nil {
		return
	}
	var cache policyCache
	if json.Unmarshal(data, &cache) != nil || cache.Version != 2 || cache.Set.Validate() != nil {
		agent.logf("policy cache ignored: invalid or incompatible version; reconnect to the v2 controller")
		return
	}
	agent.mu.Lock()
	agent.set = cache.Set
	agent.setLoaded = true
	for _, id := range cache.Bindings {
		agent.known[id] = true
	}
	agent.mu.Unlock()
	_ = agent.creds.setEndpoint(cache.Set.OpenBao)
}

func (agent *Agent) saveCacheLocked() {
	known := make([]string, 0, len(agent.known))
	for id := range agent.known {
		known = append(known, id)
	}
	sort.Strings(known)
	data, err := json.Marshal(policyCache{Version: 2, Set: agent.set, Bindings: known})
	if err != nil {
		return
	}
	if err := writeOwnerOnly(agent.paths.PolicyCache(), data, false); err != nil {
		agent.logf("policy cache not written")
	}
}

// fullReconcile lists every container and reconciles the complete set.
func (agent *Agent) fullReconcile(ctx context.Context) error {
	listCtx, cancel := context.WithTimeout(ctx, agent.config.EngineTimeout)
	summaries, err := agent.engine.List(listCtx)
	cancel()
	if err != nil {
		return err
	}
	observed := map[string]engine.Container{}
	var indeterminate []string
	for _, summary := range summaries {
		inspectCtx, cancel := context.WithTimeout(ctx, agent.config.EngineTimeout)
		container, err := agent.engine.Inspect(inspectCtx, summary.ID)
		cancel()
		switch {
		case err == nil:
			observed[container.ID] = container
		case !errors.Is(err, engine.ErrNotFound):
			indeterminate = append(indeterminate, summary.ID)
		}
	}
	agent.mu.Lock()
	// A listed container whose inspect failed still exists: keep its last
	// observation so its consumer directory, which the container mounts by
	// inode, is not removed and recreated.
	complete := true
	for _, id := range indeterminate {
		if previous, ok := agent.containers[id]; ok {
			observed[id] = previous
		} else {
			complete = false
		}
	}
	for id := range agent.containers {
		if _, ok := observed[id]; !ok {
			agent.containerGoneLocked(id)
		}
	}
	for id, container := range observed {
		if _, ok := agent.containers[id]; !ok {
			agent.record(events.Event{Operation: events.OperationContainerObserved, Outcome: events.OutcomeOK, ContainerKey: primaryKey(container)})
		}
		agent.containers[id] = container
	}
	if complete {
		// An uninspected container may carry a journaled name.
		agent.reportInterruptedRecreatesLocked(observed)
	}
	agent.applyLocked(ctx)
	agent.mu.Unlock()
	agent.sendInventory()
	agent.creds.reportUnrecorded()
	return nil
}

func (agent *Agent) reconcileContainer(ctx context.Context, id string) {
	inspectCtx, cancel := context.WithTimeout(ctx, agent.config.EngineTimeout)
	container, err := agent.engine.Inspect(inspectCtx, id)
	cancel()
	agent.mu.Lock()
	switch {
	case errors.Is(err, engine.ErrNotFound):
		agent.containerGoneLocked(id)
	case err != nil:
		agent.mu.Unlock()
		return
	default:
		if _, ok := agent.containers[id]; !ok {
			agent.record(events.Event{Operation: events.OperationContainerObserved, Outcome: events.OutcomeOK, ContainerKey: primaryKey(container)})
		}
		agent.containers[id] = container
	}
	agent.applyLocked(ctx)
	agent.mu.Unlock()
	agent.sendInventory()
}

func (agent *Agent) containerGoneLocked(id string) {
	container, ok := agent.containers[id]
	if !ok {
		return
	}
	delete(agent.containers, id)
	agent.record(events.Event{Operation: events.OperationContainerGone, Outcome: events.OutcomeOK, ContainerKey: primaryKey(container)})
}

func (agent *Agent) watchEngine(ctx context.Context) {
	delay := time.Second
	for ctx.Err() == nil {
		stream, failure := agent.engine.Events(ctx)
		// Events may have been missed while the stream was down.
		_ = agent.fullReconcile(ctx)
	read:
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-stream:
				if !ok {
					break read
				}
				delay = time.Second
				select {
				case agent.reconcile <- event.ID:
				default:
				}
			}
		}
		<-failure
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		if delay < time.Minute {
			delay *= 2
		}
	}
}

// governing returns the binding that governs container: the policy-set
// binding on the earliest key in the container's precedence order.
func (agent *Agent) governingLocked(container engine.Container) (protocol.Binding, bool) {
	keys := Keys(container)
	for _, key := range keys {
		for _, candidate := range agent.set.Bindings {
			if candidate.Key == key {
				return candidate, true
			}
		}
	}
	return protocol.Binding{}, false
}

func (agent *Agent) bindingLocked(id string) (protocol.Binding, bool) {
	for _, candidate := range agent.set.Bindings {
		if candidate.Binding == id {
			return candidate, true
		}
	}
	return protocol.Binding{}, false
}

func (agent *Agent) bindingKey(id string) string {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	if bound, ok := agent.bindingLocked(id); ok {
		return events.ContainerKey(string(bound.Key.Kind), bound.Key.Value)
	}
	return ""
}

// applyLocked makes consumer directories, sockets, and contract results
// match the observed containers and the current policy set.
func (agent *Agent) applyLocked(ctx context.Context) {
	desired := map[string]protocol.Binding{}
	// A name binding identifies its mount source even before a container exists.
	for _, bound := range agent.set.Bindings {
		if bound.Key.Kind == protocol.KeyName && consumer.ValidName(bound.Key.Value) {
			desired[bound.Key.Value] = bound
		}
	}
	governed := map[string][]engine.Container{}
	for _, container := range agent.containers {
		bound, ok := agent.governingLocked(container)
		if !ok || !consumer.ValidName(container.ShortName()) {
			continue
		}
		desired[container.ShortName()] = bound
		governed[bound.Binding] = append(governed[bound.Binding], container)
	}
	for name, state := range agent.consumers {
		if _, ok := desired[name]; ok || agent.recreating[name] {
			continue
		}
		agent.removeConsumerLocked(name, state)
	}
	for name, bound := range desired {
		agent.ensureConsumerLocked(name, bound)
	}
	for id, containers := range governed {
		bound, _ := agent.bindingLocked(id)
		agent.checkLocked(ctx, bound, containers)
	}
}

func (agent *Agent) ensureConsumerLocked(name string, bound protocol.Binding) {
	group := bound.Policy.Contract.AccessGroup
	state, ok := agent.consumers[name]
	if ok {
		state.binding = bound.Binding
		if !sameGroup(state.group, group) {
			if err := state.directory.SetGroup(group); err == nil {
				state.group = group
			}
		}
		return
	}
	directory, err := agent.root.Open(name, group)
	if err != nil {
		agent.logf("consumer directory unavailable")
		return
	}
	state = &consumerState{directory: directory, binding: bound.Binding, group: group}
	agent.consumers[name] = state
	if agent.endpoints == nil {
		return
	}
	lookup := agent.lookupFor(name)
	if listener, err := directory.Listen(consumer.VaultSocket); err == nil {
		state.listeners = append(state.listeners, listener)
		go agent.endpoints.ServeVault(listener, lookup, agent.record)
	}
	if listener, err := directory.Listen(consumer.SSHAgentSocket); err == nil {
		state.listeners = append(state.listeners, listener)
		go agent.endpoints.ServeSSHAgent(listener, lookup, agent.record)
	}
}

func sameGroup(left, right *uint32) bool {
	if left == nil || right == nil {
		return left == right
	}
	return *left == *right
}

func (agent *Agent) removeConsumerLocked(name string, state *consumerState) {
	for _, listener := range state.listeners {
		_ = listener.Close()
	}
	// The controller withdraws unmatched bindings during a manual recreate.
	// Leave the mount source in place so Docker cannot create it as root.
	if err := state.directory.RemoveSockets(); err != nil {
		agent.logf("consumer sockets not fully removed")
	}
	_ = state.directory.Close()
	delete(agent.consumers, name)
}

// lookupFor returns the per-request binding lookup for one consumer.
func (agent *Agent) lookupFor(name string) binding.Lookup {
	return func() (binding.View, bool) {
		agent.mu.Lock()
		state, ok := agent.consumers[name]
		if !ok {
			agent.mu.Unlock()
			return binding.View{}, false
		}
		bound, ok := agent.bindingLocked(state.binding)
		set := agent.set
		agent.mu.Unlock()
		if !ok {
			return binding.View{}, false
		}
		view := binding.View{
			ID: bound.Binding, ContainerKey: events.ContainerKey(string(bound.Key.Kind), bound.Key.Value),
			Policy: bound.Policy, OpenBao: set.OpenBao, Client: agent.creds.openBaoClient(),
			Mounts: binding.Mounts{Transit: orDefault(set.OpenBao.TransitMount, config.DefaultTransitMount), SSH: orDefault(set.OpenBao.SSHMount, config.DefaultSSHMount)},
		}
		view.Token, view.HasToken = agent.creds.current(bound.Binding)
		return view, true
	}
}

func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

// checkLocked validates every container governed by a binding and reports
// the binding's combined result when it changes.
func (agent *Agent) checkLocked(ctx context.Context, bound protocol.Binding, containers []engine.Container) {
	if agent.anyRecreatingLocked(containers) {
		return
	}
	failedSet := map[protocol.FailedItem]bool{}
	for _, container := range containers {
		state := agent.consumers[container.ShortName()]
		if state == nil || state.binding != bound.Binding || len(state.listeners) != 2 || !sameGroup(state.group, bound.Policy.Contract.AccessGroup) {
			failedSet[protocol.FailedConsumerDirectory] = true
		}
		if !contract.SocketReachable(container, bound.Policy.Contract.AccessGroup) {
			failedSet[protocol.FailedSocketAccess] = true
		}
		for _, item := range contract.Check(container, bound.Policy.Contract, agent.root.DirectoryPath(container.ShortName()), agent.canAssign) {
			failedSet[item] = true
		}
	}
	result := protocol.ContractResult{Binding: bound.Binding, Outcome: protocol.OutcomeConforming}
	if len(failedSet) > 0 {
		result.Outcome = protocol.OutcomeNonConforming
		for _, item := range protocol.FailedItems {
			if failedSet[item] {
				result.FailedItems = append(result.FailedItems, item)
			}
		}
	}
	if previous, ok := agent.results[bound.Binding]; ok && (previous.Outcome == protocol.OutcomeRecreated || previous.Outcome == protocol.OutcomeRecreateFailed) && result.Outcome == protocol.OutcomeNonConforming {
		// A failed recreate stays reported until the next binding or request.
		if previous.Outcome == protocol.OutcomeRecreateFailed {
			return
		}
	}
	agent.reportLocked(result)
}

func (agent *Agent) anyRecreatingLocked(containers []engine.Container) bool {
	for _, container := range containers {
		if agent.recreating[container.ShortName()] {
			return true
		}
	}
	return false
}

func (agent *Agent) reportLocked(result protocol.ContractResult) {
	previous, ok := agent.results[result.Binding]
	if ok && sameResult(previous, result) {
		return
	}
	agent.results[result.Binding] = result
	code := events.ErrorNone
	if result.Outcome == protocol.OutcomeNonConforming || result.Outcome == protocol.OutcomeRecreateFailed {
		code = events.ErrorPolicyDenied
		for _, item := range result.FailedItems {
			if item == protocol.FailedRecreateNotAllowed {
				code = events.ErrorRecreateNotAllowed
			}
		}
		if result.Outcome == protocol.OutcomeRecreateFailed {
			code = events.ErrorEngineUnavailable
		}
	}
	if result.Outcome == protocol.OutcomeConforming || result.Outcome == protocol.OutcomeNonConforming {
		bound, _ := agent.bindingLocked(result.Binding)
		agent.recordBinding(bound, events.Event{Operation: events.OperationContractChecked, Outcome: outcomeOf(code), ErrorCode: code,
			Binding: result.Binding, ContainerKey: events.ContainerKey(string(bound.Key.Kind), bound.Key.Value)})
	}
	if agent.session != nil {
		agent.session.send(result)
	}
}

func sameResult(left, right protocol.ContractResult) bool {
	if left.Outcome != right.Outcome || left.ContainerID != right.ContainerID || left.Reason != right.Reason || len(left.FailedItems) != len(right.FailedItems) {
		return false
	}
	for index := range left.FailedItems {
		if left.FailedItems[index] != right.FailedItems[index] {
			return false
		}
	}
	return true
}

// applyPolicySet installs a policy set from the controller: bindings absent
// from it are retired, new bindings are recorded, and new recreate-enforced
// bindings recreate their non-conforming containers once.
func (agent *Agent) applyPolicySet(ctx context.Context, set protocol.PolicySet) {
	if err := agent.creds.setEndpoint(set.OpenBao); err != nil {
		agent.logf("OpenBao endpoint invalid")
	}
	agent.mu.Lock()
	previous := map[string]protocol.Binding{}
	for _, bound := range agent.set.Bindings {
		previous[bound.Binding] = bound
	}
	agent.set = set
	agent.setLoaded = true
	current := map[string]bool{}
	var fresh []protocol.Binding
	for _, bound := range set.Bindings {
		current[bound.Binding] = true
		old, ok := previous[bound.Binding]
		if !ok || old.Assignment != bound.Assignment {
			// The controller issues a credential for the new policy; a
			// delivery for the old policy must not install its token.
			generation := agent.creds.invalidate(bound.Binding)
			go agent.creds.retry(ctx, bound.Binding, generation)
		}
		if !ok || old.Assignment != bound.Assignment {
			agent.recordBinding(bound, events.Event{Operation: events.OperationBindingReceived, Outcome: events.OutcomeOK, Binding: bound.Binding,
				ContainerKey: events.ContainerKey(string(bound.Key.Kind), bound.Key.Value)})
		}
		if !agent.known[bound.Binding] {
			agent.known[bound.Binding] = true
			fresh = append(fresh, bound)
		}
	}
	// A binding absent from the set no longer matches a container: its
	// container was destroyed or the binding was deleted. Bindings whose
	// container is being recreated are kept through the gap.
	var retired []protocol.Binding
	for id, bound := range previous {
		if !current[id] && !agent.recreatingBindingLocked(id) {
			retired = append(retired, bound)
			delete(agent.results, id)
		}
	}
	agent.saveCacheLocked()
	agent.applyLocked(ctx)
	var recreate []engine.Container
	var recreateBindings []protocol.Binding
	for _, bound := range fresh {
		if bound.Policy.Contract.Enforcement != policy.EnforcementRecreate {
			continue
		}
		for _, container := range agent.containers {
			governing, ok := agent.governingLocked(container)
			if !ok || governing.Binding != bound.Binding {
				continue
			}
			if len(contract.Check(container, bound.Policy.Contract, agent.root.DirectoryPath(container.ShortName()), agent.canAssign)) == 0 {
				continue
			}
			recreate = append(recreate, container)
			recreateBindings = append(recreateBindings, bound)
		}
	}
	agent.mu.Unlock()
	for _, bound := range retired {
		agent.retire(bound)
	}
	for index, container := range recreate {
		agent.startRecreate(ctx, recreateBindings[index], container)
	}
}

func (agent *Agent) retire(bound protocol.Binding) {
	agent.creds.retire(bound.Binding)
	agent.recordBinding(bound, events.Event{Operation: events.OperationBindingRetired, Outcome: events.OutcomeOK, Binding: bound.Binding,
		ContainerKey: events.ContainerKey(string(bound.Key.Kind), bound.Key.Value)})
}

// unbind retires a binding immediately on the controller's request.
func (agent *Agent) unbind(ctx context.Context, id string) {
	agent.mu.Lock()
	bound, ok := agent.bindingLocked(id)
	if ok {
		var kept []protocol.Binding
		for _, candidate := range agent.set.Bindings {
			if candidate.Binding != id {
				kept = append(kept, candidate)
			}
		}
		agent.set.Bindings = kept
		delete(agent.known, id)
		delete(agent.results, id)
		agent.saveCacheLocked()
		agent.applyLocked(ctx)
	}
	agent.mu.Unlock()
	if ok {
		agent.retire(bound)
	} else {
		agent.creds.retire(id)
	}
}

// requestRecreate handles an operator-requested recreate for a binding.
func (agent *Agent) requestRecreate(ctx context.Context, id string) {
	agent.mu.Lock()
	bound, ok := agent.bindingLocked(id)
	var targets []engine.Container
	if ok {
		for _, container := range agent.containers {
			if governing, governed := agent.governingLocked(container); governed && governing.Binding == id {
				targets = append(targets, container)
			}
		}
	}
	agent.mu.Unlock()
	for _, container := range targets {
		agent.startRecreate(ctx, bound, container)
	}
}

// reportAccessor tells the controller which token a binding holds, so the
// controller can revoke it when the binding is deleted.
func (agent *Agent) reportAccessor(id, assignment, accessor string) {
	agent.mu.Lock()
	session := agent.session
	agent.mu.Unlock()
	if session != nil {
		session.send(protocol.TokenAccessor{Binding: id, Assignment: assignment, Accessor: accessor})
	}
}

func (agent *Agent) requestCredential(id string) {
	agent.mu.Lock()
	session := agent.session
	agent.mu.Unlock()
	if session != nil {
		session.send(protocol.CredentialRequest{Binding: id})
	}
}

// Keys returns a container's candidate keys in precedence order.
func Keys(container engine.Container) []protocol.Key {
	var keys []protocol.Key
	labels := container.Config.Labels
	if folder := labels["devcontainer.local_folder"]; folder != "" {
		value := folder
		if configFile := labels["devcontainer.config_file"]; configFile != "" {
			value += "|" + configFile
		}
		keys = append(keys, protocol.Key{Kind: protocol.KeyDevcontainer, Value: value})
	}
	if project, service := labels["com.docker.compose.project"], labels["com.docker.compose.service"]; project != "" && service != "" {
		keys = append(keys, protocol.Key{Kind: protocol.KeyCompose, Value: project + "/" + service})
	}
	if name := container.ShortName(); name != "" {
		keys = append(keys, protocol.Key{Kind: protocol.KeyName, Value: name})
	}
	var valid []protocol.Key
	for _, key := range keys {
		if key.Validate() == nil {
			valid = append(valid, key)
		}
	}
	return valid
}

func primaryKey(container engine.Container) string {
	keys := Keys(container)
	if len(keys) == 0 {
		return ""
	}
	return events.ContainerKey(string(keys[0].Kind), keys[0].Value)
}

// Report builds the inventory entry for a container.
func Report(container engine.Container) (protocol.Container, bool) {
	state := protocol.State(container.State.Status)
	switch state {
	case protocol.StateCreated, protocol.StateRunning, protocol.StatePaused, protocol.StateRestarting, protocol.StateExited, protocol.StateDead:
	case "removing":
		state = protocol.StateDead
	default:
		state = protocol.StateExited
	}
	report := protocol.Container{ID: container.ID, Name: container.ShortName(), State: state, Image: container.Config.Image, Keys: Keys(container)}
	if len(report.Image) > 512 {
		report.Image = ""
	}
	for _, mount := range container.Mounts {
		report.Mounts = append(report.Mounts, protocol.Mount{Source: mount.Source, Target: mount.Destination})
	}
	seen := map[string]bool{}
	for _, entry := range container.Config.Env {
		name := entry
		if index := indexByte(entry, '='); index >= 0 {
			name = entry[:index]
		}
		if name != "" && !seen[name] {
			seen[name] = true
			report.EnvNames = append(report.EnvNames, name)
		}
	}
	sort.Strings(report.EnvNames)
	return report, report.Validate() == nil
}

func indexByte(value string, character byte) int {
	for index := 0; index < len(value); index++ {
		if value[index] == character {
			return index
		}
	}
	return -1
}

func (agent *Agent) inventory() protocol.Inventory {
	agent.mu.Lock()
	defer agent.mu.Unlock()
	inventory := protocol.Inventory{Containers: []protocol.Container{}}
	ids := make([]string, 0, len(agent.containers))
	for id := range agent.containers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		if report, ok := Report(agent.containers[id]); ok && len(inventory.Containers) < 1024 {
			report.ConsumerDirectory = agent.root.DirectoryPath(agent.containers[id].ShortName())
			inventory.Containers = append(inventory.Containers, report)
		}
	}
	return inventory
}

func (agent *Agent) sendInventory() {
	agent.mu.Lock()
	session := agent.session
	recreating := len(agent.recreating) > 0
	agent.mu.Unlock()
	// A recreate removes and creates a container; the inventory is sent
	// once it finishes so the controller never sees the gap.
	if recreating {
		return
	}
	if session != nil {
		session.send(agent.inventory())
	}
}

func (agent *Agent) recordBinding(bound protocol.Binding, event events.Event) {
	for _, name := range bound.Policy.Names() {
		event.Policy = name
		agent.record(event)
	}
}
