// ---
// relationships:
//   implements: controller
// ---

// Package store owns the controller's durable SQLite state: agents,
// policies, bindings, the latest inventory per agent, contract results,
// operators, and web sessions. It holds references to OpenBao objects and
// never a token, secret identifier, or wrapping token.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

var (
	// ErrNotFound means the requested record does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict means the change conflicts with existing state.
	ErrConflict = errors.New("conflict")
)

// Store is the controller database.
type Store struct {
	db *sql.DB
}

var migrations = []string{
	`CREATE TABLE agents (
		fingerprint TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		public_key TEXT NOT NULL,
		state TEXT NOT NULL CHECK (state IN ('pending', 'approved', 'rejected')),
		first_seen INTEGER NOT NULL,
		decided_at INTEGER,
		decided_by TEXT NOT NULL DEFAULT '',
		agent_version TEXT NOT NULL DEFAULT '',
		allow_recreate INTEGER NOT NULL DEFAULT 0,
		last_connected INTEGER,
		last_report INTEGER
	);
	CREATE UNIQUE INDEX agents_approved_name ON agents(name) WHERE state = 'approved';
	CREATE TABLE policies (
		name TEXT PRIMARY KEY,
		revision INTEGER NOT NULL,
		document TEXT NOT NULL,
		saved_at INTEGER NOT NULL,
		saved_by TEXT NOT NULL DEFAULT ''
	);
	CREATE TABLE bindings (
		id TEXT PRIMARY KEY,
		agent TEXT NOT NULL,
		key_kind TEXT NOT NULL,
		key_value TEXT NOT NULL,
		policy TEXT NOT NULL REFERENCES policies(name),
		role TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		created_by TEXT NOT NULL DEFAULT '',
		UNIQUE (agent, key_kind, key_value)
	);
	CREATE TABLE inventories (
		agent TEXT PRIMARY KEY,
		containers TEXT NOT NULL,
		reported_at INTEGER NOT NULL
	);
	CREATE TABLE retired_bindings (
		id TEXT PRIMARY KEY,
		agent TEXT NOT NULL,
		retired_at INTEGER NOT NULL
	);
	CREATE TABLE binding_tokens (
		binding TEXT PRIMARY KEY REFERENCES bindings(id) ON DELETE CASCADE,
		accessor TEXT NOT NULL,
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE contract_results (
		binding TEXT PRIMARY KEY REFERENCES bindings(id) ON DELETE CASCADE,
		outcome TEXT NOT NULL,
		failed_items TEXT NOT NULL,
		container_id TEXT NOT NULL DEFAULT '',
		reason TEXT NOT NULL DEFAULT '',
		updated_at INTEGER NOT NULL
	);
	CREATE TABLE operators (
		subject TEXT PRIMARY KEY,
		display_name TEXT NOT NULL,
		email TEXT NOT NULL,
		last_sign_in INTEGER NOT NULL
	);
	CREATE TABLE web_sessions (
		id_hash TEXT PRIMARY KEY,
		subject TEXT NOT NULL REFERENCES operators(subject),
		admitted_group TEXT NOT NULL,
		csrf TEXT NOT NULL,
		created_at INTEGER NOT NULL,
		expires_at INTEGER NOT NULL
	);`,
}

// Open opens or creates the database at path, applying migrations.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create state directory: %w", err)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("secure database: %w", err)
	}
	return store, nil
}

// Close closes the database.
func (store *Store) Close() error { return store.db.Close() }

func (store *Store) migrate() error {
	var version int
	if err := store.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if version > len(migrations) {
		return errors.New("database schema is newer than this controller")
	}
	for index := version; index < len(migrations); index++ {
		transaction, err := store.db.Begin()
		if err != nil {
			return err
		}
		if _, err := transaction.Exec(migrations[index]); err != nil {
			_ = transaction.Rollback()
			return fmt.Errorf("apply migration %d: %w", index+1, err)
		}
		if _, err := transaction.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, index+1)); err != nil {
			_ = transaction.Rollback()
			return err
		}
		if err := transaction.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func unix(value time.Time) int64 { return value.UTC().UnixNano() }

func fromUnix(value sql.NullInt64) time.Time {
	if !value.Valid {
		return time.Time{}
	}
	return time.Unix(0, value.Int64).UTC()
}

// NewID returns a random binding-style identifier with the given prefix.
func NewID(prefix string) string {
	var data [8]byte
	if _, err := rand.Read(data[:]); err != nil {
		panic(err)
	}
	return prefix + hex.EncodeToString(data[:])
}

// AgentState is the closed agent approval vocabulary.
type AgentState string

const (
	AgentPending  AgentState = "pending"
	AgentApproved AgentState = "approved"
	AgentRejected AgentState = "rejected"
)

// Agent is one agent key and its approval state.
type Agent struct {
	Fingerprint   string
	Name          string
	PublicKey     string
	State         AgentState
	FirstSeen     time.Time
	DecidedAt     time.Time
	DecidedBy     string
	AgentVersion  string
	AllowRecreate bool
	LastConnected time.Time
	LastReport    time.Time
}

const agentColumns = `fingerprint, name, public_key, state, first_seen, decided_at, decided_by, agent_version, allow_recreate, last_connected, last_report`

func scanAgent(row interface{ Scan(...any) error }) (Agent, error) {
	var agent Agent
	var firstSeen int64
	var decidedAt, lastConnected, lastReport sql.NullInt64
	var allowRecreate int
	if err := row.Scan(&agent.Fingerprint, &agent.Name, &agent.PublicKey, &agent.State, &firstSeen,
		&decidedAt, &agent.DecidedBy, &agent.AgentVersion, &allowRecreate, &lastConnected, &lastReport); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Agent{}, ErrNotFound
		}
		return Agent{}, err
	}
	agent.FirstSeen = time.Unix(0, firstSeen).UTC()
	agent.DecidedAt = fromUnix(decidedAt)
	agent.LastConnected = fromUnix(lastConnected)
	agent.LastReport = fromUnix(lastReport)
	agent.AllowRecreate = allowRecreate != 0
	return agent, nil
}

// RecordKey returns the agent record for a presented key, recording it as
// pending with the presented name when the key is unknown. A pending key
// takes the most recently presented name, because SSH reports a key before
// proving possession of it and the operator decides by fingerprint.
func (store *Store) RecordKey(ctx context.Context, fingerprint, name, publicKey string, now time.Time) (Agent, error) {
	_, err := store.db.ExecContext(ctx, `INSERT INTO agents (fingerprint, name, public_key, state, first_seen)
		VALUES (?, ?, ?, 'pending', ?) ON CONFLICT(fingerprint) DO UPDATE SET name = excluded.name WHERE state = 'pending'`,
		fingerprint, name, publicKey, unix(now))
	if err != nil {
		return Agent{}, err
	}
	return store.Agent(ctx, fingerprint)
}

// PendingCount returns the number of pending agent keys.
func (store *Store) PendingCount(ctx context.Context) (int, error) {
	var count int
	err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM agents WHERE state = 'pending'`).Scan(&count)
	return count, err
}

// Agent returns one agent by key fingerprint.
func (store *Store) Agent(ctx context.Context, fingerprint string) (Agent, error) {
	return scanAgent(store.db.QueryRowContext(ctx, `SELECT `+agentColumns+` FROM agents WHERE fingerprint = ?`, fingerprint))
}

// ApprovedAgent returns the approved agent with name.
func (store *Store) ApprovedAgent(ctx context.Context, name string) (Agent, error) {
	return scanAgent(store.db.QueryRowContext(ctx, `SELECT `+agentColumns+` FROM agents WHERE name = ? AND state = 'approved'`, name))
}

// Agents lists every agent, pending first, then by name.
func (store *Store) Agents(ctx context.Context) ([]Agent, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT `+agentColumns+` FROM agents
		ORDER BY CASE state WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END, name, first_seen`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var agents []Agent
	for rows.Next() {
		agent, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		agents = append(agents, agent)
	}
	return agents, rows.Err()
}

// DecideAgent approves or rejects a pending agent key. Approval fails with
// ErrConflict when another approved agent already uses the name.
func (store *Store) DecideAgent(ctx context.Context, fingerprint string, state AgentState, operator string, now time.Time) (Agent, error) {
	if state != AgentApproved && state != AgentRejected {
		return Agent{}, errors.New("invalid decision")
	}
	result, err := store.db.ExecContext(ctx, `UPDATE agents SET state = ?, decided_at = ?, decided_by = ?
		WHERE fingerprint = ? AND state = 'pending'`, state, unix(now), operator, fingerprint)
	if err != nil {
		if isConstraint(err) {
			return Agent{}, ErrConflict
		}
		return Agent{}, err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return Agent{}, ErrNotFound
	}
	return store.Agent(ctx, fingerprint)
}

// RecordConnection records a session's hello.
func (store *Store) RecordConnection(ctx context.Context, fingerprint, version string, allowRecreate bool, now time.Time) error {
	_, err := store.db.ExecContext(ctx, `UPDATE agents SET agent_version = ?, allow_recreate = ?, last_connected = ? WHERE fingerprint = ?`,
		version, boolInt(allowRecreate), unix(now), fingerprint)
	return err
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

// SavePolicy records a policy, incrementing its revision, and returns the
// stored document.
func (store *Store) SavePolicy(ctx context.Context, document policy.Policy, operator string, now time.Time) (policy.Policy, error) {
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return policy.Policy{}, err
	}
	defer transaction.Rollback()
	var revision int
	err = transaction.QueryRowContext(ctx, `SELECT revision FROM policies WHERE name = ?`, document.Name).Scan(&revision)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return policy.Policy{}, err
	}
	saved := document.Clone()
	saved.Revision = revision + 1
	encoded, err := json.Marshal(saved)
	if err != nil {
		return policy.Policy{}, err
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO policies (name, revision, document, saved_at, saved_by) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET revision = excluded.revision, document = excluded.document, saved_at = excluded.saved_at, saved_by = excluded.saved_by`,
		saved.Name, saved.Revision, string(encoded), unix(now), operator); err != nil {
		return policy.Policy{}, err
	}
	return saved, transaction.Commit()
}

// StoredPolicy is a policy with its save metadata.
type StoredPolicy struct {
	Policy  policy.Policy
	SavedAt time.Time
	SavedBy string
}

// Policy returns one policy.
func (store *Store) Policy(ctx context.Context, name string) (StoredPolicy, error) {
	return scanPolicy(store.db.QueryRowContext(ctx, `SELECT document, saved_at, saved_by FROM policies WHERE name = ?`, name))
}

// Policies lists every policy by name.
func (store *Store) Policies(ctx context.Context) ([]StoredPolicy, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT document, saved_at, saved_by FROM policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []StoredPolicy
	for rows.Next() {
		stored, err := scanPolicy(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, stored)
	}
	return policies, rows.Err()
}

func scanPolicy(row interface{ Scan(...any) error }) (StoredPolicy, error) {
	var document string
	var savedAt int64
	var stored StoredPolicy
	if err := row.Scan(&document, &savedAt, &stored.SavedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return StoredPolicy{}, ErrNotFound
		}
		return StoredPolicy{}, err
	}
	decoded, err := policy.Decode([]byte(document))
	if err != nil {
		return StoredPolicy{}, err
	}
	stored.Policy = decoded
	stored.SavedAt = time.Unix(0, savedAt).UTC()
	return stored, nil
}

// Binding pairs a policy with a container key on one agent.
type Binding struct {
	ID        string
	Agent     string
	Key       protocol.Key
	Policy    string
	Role      string
	CreatedAt time.Time
	CreatedBy string
}

const bindingColumns = `id, agent, key_kind, key_value, policy, role, created_at, created_by`

func scanBinding(row interface{ Scan(...any) error }) (Binding, error) {
	var binding Binding
	var createdAt int64
	if err := row.Scan(&binding.ID, &binding.Agent, &binding.Key.Kind, &binding.Key.Value, &binding.Policy,
		&binding.Role, &createdAt, &binding.CreatedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Binding{}, ErrNotFound
		}
		return Binding{}, err
	}
	binding.CreatedAt = time.Unix(0, createdAt).UTC()
	return binding, nil
}

// CreateBinding records a binding. It fails with ErrConflict when the key is
// already bound on the agent.
func (store *Store) CreateBinding(ctx context.Context, binding Binding) error {
	_, err := store.db.ExecContext(ctx, `INSERT INTO bindings (`+bindingColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		binding.ID, binding.Agent, binding.Key.Kind, binding.Key.Value, binding.Policy, binding.Role,
		unix(binding.CreatedAt), binding.CreatedBy)
	if isConstraint(err) {
		return ErrConflict
	}
	return err
}

// ChangeBindingPolicy changes a binding's policy.
func (store *Store) ChangeBindingPolicy(ctx context.Context, id, policyName string) error {
	result, err := store.db.ExecContext(ctx, `UPDATE bindings SET policy = ? WHERE id = ?`, policyName, id)
	if err != nil {
		if isConstraint(err) {
			return ErrNotFound
		}
		return err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return ErrNotFound
	}
	return nil
}

// RetireBinding removes a binding and records that it belonged to its
// agent, so a token accessor the agent reports for it later can still be
// revoked. It returns the accessor last recorded for the binding, or an
// empty string when none was, read in the same transaction as the removal
// so no report lands between them. It fails with ErrNotFound when the
// binding does not exist.
func (store *Store) RetireBinding(ctx context.Context, id string, now time.Time) (string, error) {
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer func() { _ = transaction.Rollback() }()
	var agent string
	if err := transaction.QueryRowContext(ctx, `SELECT agent FROM bindings WHERE id = ?`, id).Scan(&agent); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	var accessor string
	err = transaction.QueryRowContext(ctx, `SELECT accessor FROM binding_tokens WHERE binding = ?`, id).Scan(&accessor)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO retired_bindings (id, agent, retired_at) VALUES (?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET agent = excluded.agent, retired_at = excluded.retired_at`, id, agent, unix(now)); err != nil {
		return "", err
	}
	if _, err := transaction.ExecContext(ctx, `DELETE FROM bindings WHERE id = ?`, id); err != nil {
		return "", err
	}
	return accessor, transaction.Commit()
}

// RetiredBindingAgent returns the agent a retired binding belonged to, or
// ErrNotFound when no binding with that identifier was retired.
func (store *Store) RetiredBindingAgent(ctx context.Context, id string) (string, error) {
	var agent string
	err := store.db.QueryRowContext(ctx, `SELECT agent FROM retired_bindings WHERE id = ?`, id).Scan(&agent)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return agent, err
}

// Binding returns one binding.
func (store *Store) Binding(ctx context.Context, id string) (Binding, error) {
	return scanBinding(store.db.QueryRowContext(ctx, `SELECT `+bindingColumns+` FROM bindings WHERE id = ?`, id))
}

// Bindings lists bindings for one agent, or every binding when agent is empty.
func (store *Store) Bindings(ctx context.Context, agent string) ([]Binding, error) {
	query := `SELECT ` + bindingColumns + ` FROM bindings`
	var arguments []any
	if agent != "" {
		query += ` WHERE agent = ?`
		arguments = append(arguments, agent)
	}
	rows, err := store.db.QueryContext(ctx, query+` ORDER BY agent, created_at`, arguments...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var bindings []Binding
	for rows.Next() {
		binding, err := scanBinding(rows)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return bindings, rows.Err()
}

// SaveInventory records an agent's latest complete inventory.
func (store *Store) SaveInventory(ctx context.Context, agent, fingerprint string, containers []protocol.Container, now time.Time) error {
	encoded, err := json.Marshal(containers)
	if err != nil {
		return err
	}
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer transaction.Rollback()
	if _, err := transaction.ExecContext(ctx, `INSERT INTO inventories (agent, containers, reported_at) VALUES (?, ?, ?)
		ON CONFLICT(agent) DO UPDATE SET containers = excluded.containers, reported_at = excluded.reported_at`,
		agent, string(encoded), unix(now)); err != nil {
		return err
	}
	if _, err := transaction.ExecContext(ctx, `UPDATE agents SET last_report = ? WHERE fingerprint = ?`, unix(now), fingerprint); err != nil {
		return err
	}
	return transaction.Commit()
}

// Inventory returns an agent's latest inventory, or nil when none was reported.
func (store *Store) Inventory(ctx context.Context, agent string) ([]protocol.Container, time.Time, error) {
	var encoded string
	var reportedAt int64
	err := store.db.QueryRowContext(ctx, `SELECT containers, reported_at FROM inventories WHERE agent = ?`, agent).Scan(&encoded, &reportedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, nil
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	var containers []protocol.Container
	if err := json.Unmarshal([]byte(encoded), &containers); err != nil {
		return nil, time.Time{}, err
	}
	return containers, time.Unix(0, reportedAt).UTC(), nil
}

// ContractResult is the latest conformance reported for a binding.
type ContractResult struct {
	Binding     string
	Outcome     protocol.Outcome
	FailedItems []protocol.FailedItem
	ContainerID string
	Reason      protocol.Reason
	UpdatedAt   time.Time
}

// SaveTokenAccessor records the accessor of a binding's current token,
// replacing the one recorded before. It fails with ErrNotFound when the
// binding does not exist.
func (store *Store) SaveTokenAccessor(ctx context.Context, binding, accessor string, now time.Time) error {
	_, err := store.db.ExecContext(ctx, `INSERT INTO binding_tokens (binding, accessor, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(binding) DO UPDATE SET accessor = excluded.accessor, updated_at = excluded.updated_at`,
		binding, accessor, unix(now))
	if isConstraint(err) {
		return ErrNotFound
	}
	return err
}

// TokenAccessor returns the accessor recorded for a binding's current
// token, or ErrNotFound when its agent has reported none.
func (store *Store) TokenAccessor(ctx context.Context, binding string) (string, error) {
	var accessor string
	err := store.db.QueryRowContext(ctx, `SELECT accessor FROM binding_tokens WHERE binding = ?`, binding).Scan(&accessor)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return accessor, err
}

// SaveContractResult records a binding's latest conformance.
func (store *Store) SaveContractResult(ctx context.Context, result protocol.ContractResult, now time.Time) error {
	items, err := json.Marshal(result.FailedItems)
	if err != nil {
		return err
	}
	_, err = store.db.ExecContext(ctx, `INSERT INTO contract_results (binding, outcome, failed_items, container_id, reason, updated_at)
		VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(binding) DO UPDATE SET outcome = excluded.outcome, failed_items = excluded.failed_items,
		container_id = excluded.container_id, reason = excluded.reason, updated_at = excluded.updated_at`,
		result.Binding, result.Outcome, string(items), result.ContainerID, result.Reason, unix(now))
	if isConstraint(err) {
		return ErrNotFound
	}
	return err
}

// ContractResults returns the latest result per binding.
func (store *Store) ContractResults(ctx context.Context) (map[string]ContractResult, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT binding, outcome, failed_items, container_id, reason, updated_at FROM contract_results`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	results := map[string]ContractResult{}
	for rows.Next() {
		var result ContractResult
		var items string
		var updatedAt int64
		if err := rows.Scan(&result.Binding, &result.Outcome, &items, &result.ContainerID, &result.Reason, &updatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(items), &result.FailedItems); err != nil {
			return nil, err
		}
		result.UpdatedAt = time.Unix(0, updatedAt).UTC()
		results[result.Binding] = result
	}
	return results, rows.Err()
}

func isConstraint(err error) bool {
	if err == nil {
		return false
	}
	type coder interface{ Code() int }
	var withCode coder
	if errors.As(err, &withCode) {
		// SQLITE_CONSTRAINT and its extended codes share the low byte 19.
		return withCode.Code()&0xff == 19
	}
	return false
}
