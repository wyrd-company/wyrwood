// ---
// relationships:
//   verifies: composable-policy-bindings
// ---

package store

import (
	"bytes"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
)

func TestVersionOneStateIsRejectedWithoutMutation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("CREATE TABLE example(value TEXT); INSERT INTO example VALUES ('preserved'); PRAGMA user_version=1;"); err != nil {
		t.Fatal(err)
	}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if store, err := Open(path); err == nil {
		store.Close()
		t.Fatal("version one accepted")
	} else if err.Error() != "controller state version 1 is unsupported" {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("refused old database was mutated")
	}
}
