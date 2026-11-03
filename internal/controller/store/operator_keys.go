// ---
// relationships:
//   implements: controller
//   uses: authenticate-operator-keys-over-ssh
// ---

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/wyrd-company/wyrwood/operator"
)

// OperatorKeyState is the closed operator key approval vocabulary.
type OperatorKeyState string

const (
	OperatorKeyPending  OperatorKeyState = "pending"
	OperatorKeyApproved OperatorKeyState = "approved"
	OperatorKeyRejected OperatorKeyState = "rejected"
	OperatorKeyRevoked  OperatorKeyState = "revoked"
)

// OperatorKey is one operator key, its approval state, and its grant.
type OperatorKey struct {
	Fingerprint string
	Label       string
	PublicKey   string
	State       OperatorKeyState
	Grant       operator.Grant
	FirstSeen   time.Time
	DecidedAt   time.Time
	DecidedBy   string
	RevokedAt   time.Time
	RevokedBy   string
	LastUsed    time.Time
}

const operatorKeyColumns = `fingerprint, label, public_key, state, grants, first_seen, decided_at, decided_by, revoked_at, revoked_by, last_used`

func scanOperatorKey(row interface{ Scan(...any) error }) (OperatorKey, error) {
	var key OperatorKey
	var grant string
	var firstSeen int64
	var decidedAt, revokedAt, lastUsed sql.NullInt64
	if err := row.Scan(&key.Fingerprint, &key.Label, &key.PublicKey, &key.State, &grant, &firstSeen,
		&decidedAt, &key.DecidedBy, &revokedAt, &key.RevokedBy, &lastUsed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return OperatorKey{}, ErrNotFound
		}
		return OperatorKey{}, err
	}
	if err := json.Unmarshal([]byte(grant), &key.Grant); err != nil {
		return OperatorKey{}, err
	}
	key.FirstSeen = time.Unix(0, firstSeen).UTC()
	key.DecidedAt = fromUnix(decidedAt)
	key.RevokedAt = fromUnix(revokedAt)
	key.LastUsed = fromUnix(lastUsed)
	return key, nil
}

// RecordOperatorKey records a presented key as pending when it is unknown. A
// pending key takes the most recently presented label. A key on the agent list
// is not recorded, so that no key is on both lists, and the result is ErrNotFound.
func (store *Store) RecordOperatorKey(ctx context.Context, fingerprint, label, publicKey string, now time.Time) (OperatorKey, error) {
	_, err := store.db.ExecContext(ctx, `INSERT INTO operator_keys (fingerprint, label, public_key, state, first_seen)
		SELECT ?, ?, ?, 'pending', ? WHERE NOT EXISTS (SELECT 1 FROM agents WHERE fingerprint = ?)
		ON CONFLICT(fingerprint) DO UPDATE SET label = excluded.label WHERE state = 'pending'`,
		fingerprint, label, publicKey, unix(now), fingerprint)
	if err != nil {
		return OperatorKey{}, err
	}
	return store.OperatorKey(ctx, fingerprint)
}

// PendingOperatorKeyCount returns the number of pending operator keys.
func (store *Store) PendingOperatorKeyCount(ctx context.Context) (int, error) {
	var count int
	err := store.db.QueryRowContext(ctx, `SELECT count(*) FROM operator_keys WHERE state = 'pending'`).Scan(&count)
	return count, err
}

// OperatorKey returns one operator key by fingerprint.
func (store *Store) OperatorKey(ctx context.Context, fingerprint string) (OperatorKey, error) {
	return scanOperatorKey(store.db.QueryRowContext(ctx, `SELECT `+operatorKeyColumns+` FROM operator_keys WHERE fingerprint = ?`, fingerprint))
}

// OperatorKeys lists every operator key, pending first, then by label.
func (store *Store) OperatorKeys(ctx context.Context) ([]OperatorKey, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT `+operatorKeyColumns+` FROM operator_keys
		ORDER BY CASE state WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 WHEN 'revoked' THEN 2 ELSE 3 END, label, first_seen`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []OperatorKey
	for rows.Next() {
		key, err := scanOperatorKey(rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// ApproveOperatorKey approves a pending key with its label and grant. The label
// fails with ErrConflict when an approved or revoked key holds it, so that one
// audit subject never names two keys.
func (store *Store) ApproveOperatorKey(ctx context.Context, fingerprint, label string, grant operator.Grant, by string, now time.Time) (OperatorKey, error) {
	encoded, err := json.Marshal(grant)
	if err != nil {
		return OperatorKey{}, err
	}
	result, err := store.db.ExecContext(ctx, `UPDATE operator_keys SET state = 'approved', label = ?, grants = ?, decided_at = ?, decided_by = ?
		WHERE fingerprint = ? AND state = 'pending'`, label, string(encoded), unix(now), by, fingerprint)
	if err != nil {
		if isConstraint(err) {
			return OperatorKey{}, ErrConflict
		}
		return OperatorKey{}, err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return OperatorKey{}, ErrNotFound
	}
	return store.OperatorKey(ctx, fingerprint)
}

// RejectOperatorKey rejects a pending key.
func (store *Store) RejectOperatorKey(ctx context.Context, fingerprint, by string, now time.Time) (OperatorKey, error) {
	result, err := store.db.ExecContext(ctx, `UPDATE operator_keys SET state = 'rejected', decided_at = ?, decided_by = ?
		WHERE fingerprint = ? AND state = 'pending'`, unix(now), by, fingerprint)
	if err != nil {
		return OperatorKey{}, err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return OperatorKey{}, ErrNotFound
	}
	return store.OperatorKey(ctx, fingerprint)
}

// RevokeOperatorKey ends an approved key. A revoked key cannot be approved again.
func (store *Store) RevokeOperatorKey(ctx context.Context, fingerprint, by string, now time.Time) (OperatorKey, error) {
	result, err := store.db.ExecContext(ctx, `UPDATE operator_keys SET state = 'revoked', revoked_at = ?, revoked_by = ?
		WHERE fingerprint = ? AND state = 'approved'`, unix(now), by, fingerprint)
	if err != nil {
		return OperatorKey{}, err
	}
	if changed, _ := result.RowsAffected(); changed == 0 {
		return OperatorKey{}, ErrNotFound
	}
	return store.OperatorKey(ctx, fingerprint)
}

// RecordOperatorKeyUse records when an approved key last opened a session.
func (store *Store) RecordOperatorKeyUse(ctx context.Context, fingerprint string, now time.Time) error {
	_, err := store.db.ExecContext(ctx, `UPDATE operator_keys SET last_used = ? WHERE fingerprint = ?`, unix(now), fingerprint)
	return err
}
