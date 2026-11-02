// ---
// relationships:
//   verifies: controller
// ---

package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/policy"
)

// schemaTables lists every table of schema 2 with its columns, so that a dump
// reads the same columns before and after a migration.
var schemaTables = map[string]string{
	"agents":           "fingerprint, name, public_key, state, first_seen, decided_at, decided_by, agent_version, allow_recreate, last_connected, last_report",
	"policies":         "name, revision, document, saved_at, saved_by",
	"bindings":         "id, agent, key_kind, key_value, settings, revision, effective, applied, role, created_at, created_by",
	"binding_policies": "binding_id, policy_name",
	"inventories":      "agent, containers, reported_at",
	"retired_bindings": "id, agent, retired_at",
	"binding_tokens":   "binding, accessor, updated_at",
	"contract_results": "binding, outcome, failed_items, container_id, reason, updated_at",
	"operators":        "subject, display_name, email, last_sign_in",
	"web_sessions":     "id_hash, subject, admitted_group, csrf, created_at, expires_at",
}

func rawDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func exec(t *testing.T, db *sql.DB, statement string, arguments ...any) {
	t.Helper()
	if _, err := db.Exec(statement, arguments...); err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
}

func userVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return version
}

func dump(t *testing.T, db *sql.DB) map[string][]string {
	t.Helper()
	result := map[string][]string{}
	for table, columns := range schemaTables {
		rows, err := db.Query(`SELECT json_array(` + columns + `) FROM ` + table + ` ORDER BY 1`)
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		result[table] = []string{}
		for rows.Next() {
			var row string
			if err := rows.Scan(&row); err != nil {
				t.Fatal(err)
			}
			result[table] = append(result[table], row)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return result
}

// populatedSchemaTwo writes state in the exact schema 2 shape, with a row in
// every table. The first-use assignment is the shape schema 2 controllers wrote.
func populatedSchemaTwo(t *testing.T) (string, policy.Effective) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "controller.db")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, path)
	exec(t, db, migrations[0])
	exec(t, db, `PRAGMA user_version = 2`)
	document := policy.New("sample", policy.StarterHCL)
	document.Revision = 3
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	effective, err := policy.Compose([]policy.Policy{document}, policy.DefaultSettings())
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(effective)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := json.Marshal(effective.Settings)
	if err != nil {
		t.Fatal(err)
	}
	exec(t, db, `INSERT INTO agents VALUES ('SHA256:a', 'host-a', 'ssh-ed25519 AAAA', 'approved', 1, 2, 'operator-1', '0.4.1', 1, 3, 4)`)
	exec(t, db, `INSERT INTO policies VALUES ('sample', 3, ?, 5, 'operator-1')`, string(encoded))
	exec(t, db, `INSERT INTO policies VALUES ('unused', 1, ?, 5, 'operator-1')`, strings.Replace(string(encoded), `"sample"`, `"unused"`, 1))
	exec(t, db, `INSERT INTO bindings VALUES ('b-1', 'host-a', 'name', 'web', ?, 2, ?, 1, 'wyrwood-host-a-b-1', 6, 'operator-1')`, string(settings), string(wire))
	exec(t, db, `INSERT INTO binding_policies VALUES ('b-1', 'sample')`)
	exec(t, db, `INSERT INTO inventories VALUES ('host-a', '[]', 7)`)
	exec(t, db, `INSERT INTO retired_bindings VALUES ('b-0', 'host-a', 8)`)
	exec(t, db, `INSERT INTO binding_tokens VALUES ('b-1', 'accessor-1', 9)`)
	exec(t, db, `INSERT INTO contract_results VALUES ('b-1', 'conforming', '[]', '', '', 10)`)
	exec(t, db, `INSERT INTO operators VALUES ('subject-1', 'Operator One', 'operator@example.invalid', 11)`)
	exec(t, db, `INSERT INTO web_sessions VALUES ('hash-1', 'subject-1', 'operators', 'csrf-1', 12, 13)`)
	return path, effective
}

func TestSchemaTwoStateMigratesWithEveryRowIntact(t *testing.T) {
	ctx := context.Background()
	path, effective := populatedSchemaTwo(t)
	db := rawDB(t, path)
	before := dump(t, db)
	for table, rows := range before {
		if len(rows) == 0 {
			t.Fatalf("fixture table %s is empty", table)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	opened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = opened.Close() })
	if got := userVersion(t, opened.db); got != schemaVersion {
		t.Fatalf("user_version = %d, want %d", got, schemaVersion)
	}
	if got := dump(t, opened.db); !reflect.DeepEqual(got, before) {
		t.Fatalf("rows changed:\nbefore %v\nafter  %v", before, got)
	}
	stored, err := opened.Policy(ctx, "sample")
	if err != nil || stored.Policy.Generation != 1 || stored.Policy.OpenBaoPolicyName() != "wyrwood-sample" {
		t.Fatalf("Policy() = %#v, %v", stored.Policy, err)
	}
	binding, err := opened.Binding(ctx, "b-1")
	if err != nil {
		t.Fatal(err)
	}
	if binding.Effective.Identity() != effective.Identity() || !binding.Applied || binding.Revision != 2 {
		t.Fatalf("binding changed: %#v", binding)
	}
	for _, name := range []string{"sample", "unused"} {
		if next, err := opened.NextPolicyGeneration(ctx, name); err != nil || next != 2 {
			t.Fatalf("NextPolicyGeneration(%s) = %d, %v, want 2", name, next, err)
		}
	}
	if next, err := opened.NextPolicyGeneration(ctx, "never-used"); err != nil || next != 1 {
		t.Fatalf("NextPolicyGeneration(never-used) = %d, %v, want 1", next, err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := Open(path)
	if err != nil {
		t.Fatalf("second Open() = %v", err)
	}
	if err := again.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFreshDatabaseStartsAtTheCurrentSchema(t *testing.T) {
	ctx := context.Background()
	opened, _ := openTest(t)
	if got := userVersion(t, opened.db); got != schemaVersion {
		t.Fatalf("user_version = %d, want %d", got, schemaVersion)
	}
	saved, err := opened.SavePolicy(ctx, policy.New("sample", policy.StarterHCL), "operator-1", time.Now())
	if err != nil || saved.Generation != 1 {
		t.Fatalf("SavePolicy() = %#v, %v", saved, err)
	}
}

// A migration that fails leaves schema 2 whole, so the older version still works.
func TestFailedMigrationLeavesSchemaTwoUnchanged(t *testing.T) {
	path, _ := populatedSchemaTwo(t)
	db := rawDB(t, path)
	// The migration adds the column, and then fails on this table.
	exec(t, db, `CREATE TABLE policy_generations (blocker TEXT)`)
	before := dump(t, db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path); err == nil {
		_ = opened.Close()
		t.Fatal("the migration succeeded over a blocking table")
	}
	db = rawDB(t, path)
	if got := userVersion(t, db); got != 2 {
		t.Fatalf("user_version = %d, want 2", got)
	}
	if got := dump(t, db); !reflect.DeepEqual(got, before) {
		t.Fatalf("rows changed: %v", got)
	}
	var columns int
	if err := db.QueryRow(`SELECT count(*) FROM pragma_table_info('policies') WHERE name = 'generation'`).Scan(&columns); err != nil {
		t.Fatal(err)
	}
	if columns != 0 {
		t.Fatal("a failed migration kept its new column")
	}
}

func TestNewerSchemaIsRefusedWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	db := rawDB(t, path)
	exec(t, db, fmt.Sprintf(`CREATE TABLE example(value TEXT); INSERT INTO example VALUES ('preserved'); PRAGMA user_version=%d;`, schemaVersion+1))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(path); err == nil {
		_ = opened.Close()
		t.Fatal("a newer schema was accepted")
	} else if err.Error() != "database schema is newer than this controller" {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a refused database was mutated")
	}
}

func TestGenerationsAreNeverUsedTwice(t *testing.T) {
	ctx := context.Background()
	opened, path := openTest(t)
	now := time.Now()
	save := func(store *Store, want int) policy.Policy {
		t.Helper()
		saved, err := store.SavePolicy(ctx, policy.New("sample", policy.StarterHCL), "operator-1", now)
		if err != nil {
			t.Fatal(err)
		}
		if saved.Generation != want || saved.Revision != 1 {
			t.Fatalf("saved = generation %d revision %d, want generation %d revision 1", saved.Generation, saved.Revision, want)
		}
		stored, err := store.Policy(ctx, "sample")
		if err != nil || stored.Policy.Generation != want {
			t.Fatalf("Policy() = %#v, %v", stored.Policy, err)
		}
		return saved
	}
	save(opened, 1)
	edit, err := opened.SavePolicy(ctx, policy.New("sample", policy.StarterHCL+"# edit\n"), "operator-1", now)
	if err != nil || edit.Generation != 1 || edit.Revision != 2 {
		t.Fatalf("edit = %#v, %v", edit, err)
	}
	if err := opened.DeletePolicy(ctx, "sample"); err != nil {
		t.Fatal(err)
	}
	if next, err := opened.NextPolicyGeneration(ctx, "sample"); err != nil || next != 2 {
		t.Fatalf("next = %d, %v", next, err)
	}
	save(opened, 2)
	if err := opened.DeletePolicy(ctx, "sample"); err != nil {
		t.Fatal(err)
	}
	if err := opened.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if next, err := reopened.NextPolicyGeneration(ctx, "sample"); err != nil || next != 3 {
		t.Fatalf("next after restart = %d, %v", next, err)
	}
	save(reopened, 3)
	list, err := reopened.Policies(ctx)
	if err != nil || len(list) != 1 || list[0].Policy.Generation != 3 {
		t.Fatalf("Policies() = %#v, %v", list, err)
	}
}

// A caller publishes to OpenBao before the commit. A generation that disagrees
// with the store must not become durable, for a new row or for a kept one.
func TestStoreRefusesAGenerationThatDisagrees(t *testing.T) {
	ctx := context.Background()
	opened, _ := openTest(t)
	now := time.Now()
	stale := policy.New("sample", policy.StarterHCL)
	stale.Generation = 3
	if _, err := opened.SavePolicy(ctx, stale, "operator-1", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("new row SavePolicy() = %v, want conflict", err)
	}
	if _, err := opened.Policy(ctx, "sample"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Policy() = %v", err)
	}
	if next, err := opened.NextPolicyGeneration(ctx, "sample"); err != nil || next != 1 {
		t.Fatalf("next = %d, %v", next, err)
	}
	if _, err := opened.SavePolicy(ctx, policy.New("sample", policy.StarterHCL), "operator-1", now); err != nil {
		t.Fatal(err)
	}
	moved := policy.New("sample", policy.StarterHCL+"# edit\n")
	moved.Generation = 2
	if _, err := opened.SavePolicy(ctx, moved, "operator-1", now); !errors.Is(err, ErrConflict) {
		t.Fatalf("kept row SavePolicy() = %v, want conflict", err)
	}
	stored, err := opened.Policy(ctx, "sample")
	if err != nil || stored.Policy.Generation != 1 || stored.Policy.Revision != 1 {
		t.Fatalf("Policy() = %#v, %v", stored.Policy, err)
	}
}

// The row and its generation record commit together.
func TestGenerationRecordCommitsWithTheRow(t *testing.T) {
	ctx := context.Background()
	opened, _ := openTest(t)
	exec(t, opened.db, `CREATE TRIGGER fail_generation BEFORE INSERT ON policy_generations BEGIN SELECT RAISE(ABORT, 'injected fault'); END`)
	if _, err := opened.SavePolicy(ctx, policy.New("sample", policy.StarterHCL), "operator-1", time.Now()); err == nil {
		t.Fatal("SavePolicy() succeeded through the fault")
	}
	if _, err := opened.Policy(ctx, "sample"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("a failed generation record left the row: %v", err)
	}
	exec(t, opened.db, `DROP TRIGGER fail_generation`)
	if next, err := opened.NextPolicyGeneration(ctx, "sample"); err != nil || next != 1 {
		t.Fatalf("next = %d, %v", next, err)
	}
}
