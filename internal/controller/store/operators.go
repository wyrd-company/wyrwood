// ---
// relationships:
//   implements: web-interface
//   uses: authenticate-operators-with-oidc
// ---

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"
)

// Operator is an identity-provider account that signed in.
type Operator struct {
	Subject     string
	DisplayName string
	Email       string
	LastSignIn  time.Time
}

// WebSession is one operator's server-side session. The cookie token is
// never stored; only its hash identifies the row.
type WebSession struct {
	IDHash        string
	Subject       string
	AdmittedGroup string
	CSRF          string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// HashSessionToken returns the stored identifier for a session cookie token.
func HashSessionToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// RecordOperator records an operator's identity at sign-in.
func (store *Store) RecordOperator(ctx context.Context, operator Operator) error {
	_, err := store.db.ExecContext(ctx, `INSERT INTO operators (subject, display_name, email, last_sign_in) VALUES (?, ?, ?, ?)
		ON CONFLICT(subject) DO UPDATE SET display_name = excluded.display_name, email = excluded.email, last_sign_in = excluded.last_sign_in`,
		operator.Subject, operator.DisplayName, operator.Email, unix(operator.LastSignIn))
	return err
}

// Operator returns one operator.
func (store *Store) Operator(ctx context.Context, subject string) (Operator, error) {
	var operator Operator
	var lastSignIn int64
	err := store.db.QueryRowContext(ctx, `SELECT subject, display_name, email, last_sign_in FROM operators WHERE subject = ?`, subject).
		Scan(&operator.Subject, &operator.DisplayName, &operator.Email, &lastSignIn)
	if errors.Is(err, sql.ErrNoRows) {
		return Operator{}, ErrNotFound
	}
	if err != nil {
		return Operator{}, err
	}
	operator.LastSignIn = time.Unix(0, lastSignIn).UTC()
	return operator, nil
}

// Operators returns every recorded operator by subject.
func (store *Store) Operators(ctx context.Context) (map[string]Operator, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT subject, display_name, email, last_sign_in FROM operators`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	operators := map[string]Operator{}
	for rows.Next() {
		var operator Operator
		var lastSignIn int64
		if err := rows.Scan(&operator.Subject, &operator.DisplayName, &operator.Email, &lastSignIn); err != nil {
			return nil, err
		}
		operator.LastSignIn = time.Unix(0, lastSignIn).UTC()
		operators[operator.Subject] = operator
	}
	return operators, rows.Err()
}

// CreateSession stores a session.
func (store *Store) CreateSession(ctx context.Context, session WebSession) error {
	_, err := store.db.ExecContext(ctx, `INSERT INTO web_sessions (id_hash, subject, admitted_group, csrf, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, session.IDHash, session.Subject, session.AdmittedGroup, session.CSRF,
		unix(session.CreatedAt), unix(session.ExpiresAt))
	return err
}

// Session returns an unexpired session by its hash.
func (store *Store) Session(ctx context.Context, idHash string, now time.Time) (WebSession, error) {
	var session WebSession
	var createdAt, expiresAt int64
	err := store.db.QueryRowContext(ctx, `SELECT id_hash, subject, admitted_group, csrf, created_at, expires_at FROM web_sessions
		WHERE id_hash = ? AND expires_at > ?`, idHash, unix(now)).
		Scan(&session.IDHash, &session.Subject, &session.AdmittedGroup, &session.CSRF, &createdAt, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return WebSession{}, ErrNotFound
	}
	if err != nil {
		return WebSession{}, err
	}
	session.CreatedAt = time.Unix(0, createdAt).UTC()
	session.ExpiresAt = time.Unix(0, expiresAt).UTC()
	return session, nil
}

// OperatorSessions lists an operator's unexpired sessions, newest first.
func (store *Store) OperatorSessions(ctx context.Context, subject string, now time.Time) ([]WebSession, error) {
	rows, err := store.db.QueryContext(ctx, `SELECT id_hash, subject, admitted_group, csrf, created_at, expires_at FROM web_sessions
		WHERE subject = ? AND expires_at > ? ORDER BY created_at DESC`, subject, unix(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var sessions []WebSession
	for rows.Next() {
		var session WebSession
		var createdAt, expiresAt int64
		if err := rows.Scan(&session.IDHash, &session.Subject, &session.AdmittedGroup, &session.CSRF, &createdAt, &expiresAt); err != nil {
			return nil, err
		}
		session.CreatedAt = time.Unix(0, createdAt).UTC()
		session.ExpiresAt = time.Unix(0, expiresAt).UTC()
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

// DeleteSession ends one session.
func (store *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := store.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE id_hash = ?`, idHash)
	return err
}

// DeleteOtherSessions ends every session of subject except keep.
func (store *Store) DeleteOtherSessions(ctx context.Context, subject, keep string) (int64, error) {
	result, err := store.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE subject = ? AND id_hash != ?`, subject, keep)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// PruneSessions deletes expired sessions.
func (store *Store) PruneSessions(ctx context.Context, now time.Time) error {
	_, err := store.db.ExecContext(ctx, `DELETE FROM web_sessions WHERE expires_at <= ?`, unix(now))
	return err
}
