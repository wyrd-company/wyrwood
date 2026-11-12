// ---
// relationships:
//   verifies:
//     - controller
//     - composable-policy-bindings
// ---

package store

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/policy"
	"github.com/wyrd-company/wyrwood/internal/protocol"
)

// schemaFour is state that the store at the base of this change wrote, with a
// row in every table: bindings on each key kind, a retired binding, an
// inventory, an accessor, a contract result, an operator, a session, a
// pending agent, a policy retirement, and an approved operator key.
//
//go:embed testdata/schema-4.sql
var schemaFour string

// tableColumns returns each table's columns as it is now, so that a later read
// can select the same columns after a migration adds one.
func tableColumns(t *testing.T, db *sql.DB) map[string][]string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, name)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	columns := map[string][]string{}
	for _, table := range tables {
		info, err := db.Query(`SELECT name FROM pragma_table_info(?) ORDER BY cid`, table)
		if err != nil {
			t.Fatal(err)
		}
		for info.Next() {
			var name string
			if err := info.Scan(&name); err != nil {
				t.Fatal(err)
			}
			columns[table] = append(columns[table], name)
		}
		if err := info.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return columns
}

func rowsOf(t *testing.T, db *sql.DB, columns map[string][]string) map[string][]string {
	t.Helper()
	result := map[string][]string{}
	for table, names := range columns {
		rows, err := db.Query(`SELECT json_array(` + strings.Join(names, ", ") + `) FROM ` + table + ` ORDER BY 1`)
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

// State written at the base opens at this schema with every row as it was, and
// every binding reads with no directory and its assignment unchanged.
func TestBaseSchemaFourStateOpensWithoutLoss(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "state", "controller.db")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	db := rawDB(t, path)
	exec(t, db, schemaFour)
	if got := userVersion(t, db); got != 4 {
		t.Fatalf("fixture user_version = %d", got)
	}
	columns := tableColumns(t, db)
	before := rowsOf(t, db, columns)
	for table, rows := range before {
		if len(rows) == 0 {
			t.Fatalf("fixture table %s is empty", table)
		}
	}
	type assignment struct {
		key      protocol.Key
		identity string
	}
	// Each assignment as the base computed it from the row.
	assignments := map[string]assignment{}
	{
		rows, err := db.Query(`SELECT id, key_kind, key_value, revision, effective FROM bindings`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var id, kind, value, encoded string
			var b Binding
			if err := rows.Scan(&id, &kind, &value, &b.Revision, &encoded); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(encoded), &b.Effective); err != nil {
				t.Fatal(err)
			}
			assignments[id] = assignment{protocol.Key{Kind: protocol.KeyKind(kind), Value: value}, b.Assignment()}
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	opened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if got := userVersion(t, opened.db); got != schemaVersion {
		t.Fatalf("user_version = %d, want %d", got, schemaVersion)
	}
	if got := rowsOf(t, opened.db, columns); !reflect.DeepEqual(got, before) {
		t.Fatalf("rows changed:\nbefore %v\nafter  %v", before, got)
	}
	bindings, err := opened.Bindings(ctx, "host-a")
	if err != nil || len(bindings) != len(assignments) {
		t.Fatalf("Bindings() = %d, %v; want %d", len(bindings), err, len(assignments))
	}
	for _, b := range bindings {
		want := assignments[b.ID]
		if b.Directory != "" || b.Key != want.key || b.Assignment() != want.identity {
			t.Fatalf("binding %s = key %v directory %q assignment %s, want %v %s", b.ID, b.Key, b.Directory, b.Assignment(), want.key, want.identity)
		}
	}
	if agents, err := opened.Agents(ctx); err != nil || len(agents) != 2 {
		t.Fatalf("Agents() = %v, %v", agents, err)
	}
	if _, err := opened.Policy(ctx, "sample"); err != nil {
		t.Fatal(err)
	}
}

func directoryBinding(id, agent string, key protocol.Key, directory string) Binding {
	effective, _ := policy.Compose([]policy.Policy{policy.New("sample", policy.StarterHCL)}, policy.DefaultSettings())
	return Binding{ID: id, Agent: agent, Key: key, Directory: directory, Policies: effective.Names(), Settings: effective.Settings,
		Effective: effective, Revision: 1, Role: "role-" + id, CreatedAt: time.Now().UTC(), CreatedBy: "operator-1"}
}

// A binding keeps its directory, and one agent's directories are distinct.
func TestBindingDirectoryIsStoredAndDistinctPerAgent(t *testing.T) {
	ctx := context.Background()
	opened, err := Open(filepath.Join(t.TempDir(), "controller.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if _, err := opened.SavePolicy(ctx, policy.New("sample", policy.StarterHCL), "operator-1", time.Now()); err != nil {
		t.Fatal(err)
	}
	compose := protocol.Key{Kind: protocol.KeyCompose, Value: "shop/web"}
	if err := opened.CreateBinding(ctx, directoryBinding("b-1", "host-a", compose, "shop-web")); err != nil {
		t.Fatal(err)
	}
	stored, err := opened.Binding(ctx, "b-1")
	if err != nil || stored.Directory != "shop-web" {
		t.Fatalf("Binding() = %+v, %v", stored, err)
	}
	other := protocol.Key{Kind: protocol.KeyDevcontainer, Value: "/src/app"}
	if err := opened.CreateBinding(ctx, directoryBinding("b-2", "host-a", other, "shop-web")); !errors.Is(err, ErrConflict) {
		t.Fatalf("a second binding with the directory = %v, want ErrConflict", err)
	}
	if err := opened.CreateBinding(ctx, directoryBinding("b-3", "host-b", compose, "shop-web")); err != nil {
		t.Fatalf("the directory on another agent = %v", err)
	}
	for _, id := range []string{"b-4", "b-5"} {
		key := protocol.Key{Kind: protocol.KeyCompose, Value: "shop/" + id}
		if err := opened.CreateBinding(ctx, directoryBinding(id, "host-a", key, "")); err != nil {
			t.Fatalf("a binding with no directory = %v", err)
		}
	}
}
