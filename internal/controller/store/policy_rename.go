// ---
// relationships:
//   implements: composable-policy-bindings
// ---

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/wyrd-company/wyrwood/internal/policy"
)

// RenamePolicy moves the policy stored as oldName to document in one
// transaction: the new row and its generation record, every binding_policies
// row, each binding's next assignment, and the retirement record of the old
// OpenBao identity. The retirement record of document's own identity, written
// before its publication, ends here. It returns ErrNotFound when oldName is not
// stored and ErrConflict when anything it was computed from has moved.
func (store *Store) RenamePolicy(ctx context.Context, oldName string, document policy.Policy, bindings []Binding, operator string, now time.Time) (policy.Policy, error) {
	transaction, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return policy.Policy{}, err
	}
	defer transaction.Rollback()
	previous, err := scanPolicy(transaction.QueryRowContext(ctx, `SELECT document, saved_at, saved_by, generation FROM policies WHERE name = ?`, oldName))
	if err != nil {
		return policy.Policy{}, err
	}
	if document.Revision != previous.Policy.Revision+1 {
		return policy.Policy{}, ErrConflict
	}
	generation, err := nextPolicyGeneration(ctx, transaction, document.Name)
	if err != nil {
		return policy.Policy{}, err
	}
	// The caller publishes this identity before the commit, so a generation that
	// disagrees with the record must not become durable.
	if document.Generation != generation {
		return policy.Policy{}, ErrConflict
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return policy.Policy{}, err
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO policies (name, revision, document, saved_at, saved_by, generation) VALUES (?, ?, ?, ?, ?, ?)`,
		document.Name, document.Revision, string(encoded), unix(now), operator, document.Generation); err != nil {
		if isConstraint(err) {
			return policy.Policy{}, ErrConflict
		}
		return policy.Policy{}, err
	}
	if _, err := transaction.ExecContext(ctx, `INSERT INTO policy_generations (name, generation) VALUES (?, ?)
		ON CONFLICT(name) DO UPDATE SET generation = excluded.generation`, document.Name, document.Generation); err != nil {
		return policy.Policy{}, err
	}
	moved, err := transaction.ExecContext(ctx, `UPDATE binding_policies SET policy_name = ? WHERE policy_name = ?`, document.Name, oldName)
	if err != nil {
		return policy.Policy{}, err
	}
	if count, err := moved.RowsAffected(); err != nil || count != int64(len(bindings)) {
		return policy.Policy{}, errors.Join(ErrConflict, err)
	}
	for _, b := range bindings {
		settings, effective, err := bindingData(b)
		if err != nil {
			return policy.Policy{}, err
		}
		updated, err := transaction.ExecContext(ctx, `UPDATE bindings SET settings=?,revision=?,effective=?,applied=0 WHERE id=? AND revision=?`, settings, b.Revision, effective, b.ID, b.Revision-1)
		if err != nil {
			return policy.Policy{}, err
		}
		if count, err := updated.RowsAffected(); err != nil || count != 1 {
			return policy.Policy{}, errors.Join(ErrConflict, err)
		}
	}
	if _, err := transaction.ExecContext(ctx, `DELETE FROM policies WHERE name = ?`, oldName); err != nil {
		return policy.Policy{}, err
	}
	if _, err := transaction.ExecContext(ctx, `DELETE FROM policy_retirements WHERE identity = ?`, document.OpenBaoPolicyName()); err != nil {
		return policy.Policy{}, err
	}
	if err := recordPolicyRetirement(ctx, transaction, previous.Policy.OpenBaoPolicyName(), now); err != nil {
		return policy.Policy{}, err
	}
	return document, transaction.Commit()
}

func recordPolicyRetirement(ctx context.Context, writer interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, identity string, now time.Time) error {
	_, err := writer.ExecContext(ctx, `INSERT INTO policy_retirements (identity, recorded_at) VALUES (?, ?) ON CONFLICT(identity) DO NOTHING`, identity, unix(now))
	return err
}

// RecordPolicyRetirement records that one exact OpenBao identity must be removed.
func (store *Store) RecordPolicyRetirement(ctx context.Context, identity string, now time.Time) error {
	return recordPolicyRetirement(ctx, store.db, identity, now)
}

// ForgetPolicyRetirement ends the record of one exact OpenBao identity.
func (store *Store) ForgetPolicyRetirement(ctx context.Context, identity string) error {
	_, err := store.db.ExecContext(ctx, `DELETE FROM policy_retirements WHERE identity = ?`, identity)
	return err
}

// PolicyRetirements lists the OpenBao identities that remain to be removed.
func (store *Store) PolicyRetirements(ctx context.Context) ([]string, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT identity FROM policy_retirements ORDER BY identity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var identities []string
	for rows.Next() {
		var identity string
		if err := rows.Scan(&identity); err != nil {
			return nil, err
		}
		identities = append(identities, identity)
	}
	return identities, rows.Err()
}
