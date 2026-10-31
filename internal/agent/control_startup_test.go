// ---
// relationships:
//   verifies: [agent, controller]
// ---

package agent

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/wyrd-company/wyrwood/internal/controller"
)

// Hold actual socket bind while controller startup creates its key and another
// filesystem consumer creates a directory. This schedule exposed the old umask.
func TestControlStartupDoesNotChangeConcurrentFilesystemModes(t *testing.T) {
	root := t.TempDir()
	baseline := filepath.Join(root, "baseline")
	if err := os.Mkdir(baseline, 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(baseline)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "control.sock")
	entered := make(chan string, 1)
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		listener, err := listenControlSocket(path, func(network string, address *net.UnixAddr) (*net.UnixListener, error) {
			listener, err := net.ListenUnix(network, address)
			entered <- address.Name
			<-release
			return listener, err
		})
		if listener != nil {
			defer listener.Close()
		}
		done <- err
	}()
	defer func() {
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	select {
	case address := <-entered:
		info, err := os.Stat(filepath.Dir(address))
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("private bind directory: %v, %v", info, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("bind was not reached")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("unsecured socket published: %v", err)
	}
	concurrent := filepath.Join(root, "concurrent")
	if err := os.Mkdir(concurrent, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(concurrent)
	if err != nil || info.Mode().Perm() != before.Mode().Perm() {
		t.Fatalf("concurrent directory mode changed: %v, %v", info, err)
	}
	state := filepath.Join(root, "controller")
	if _, err := controller.LoadOrCreateHostKey(state); err != nil {
		t.Fatalf("concurrent controller startup: %v", err)
	}
	for _, entry := range []struct {
		path string
		mode os.FileMode
	}{
		{filepath.Join(state, "ssh"), 0o700}, {controller.HostKeyPath(state), 0o600},
	} {
		info, err := os.Stat(entry.path)
		if err != nil || info.Mode().Perm() != entry.mode {
			t.Fatalf("%s mode: %v, %v", entry.path, info, err)
		}
	}
}

func TestControlSocketPublishedSecuredAndRemoved(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := listenControlSocket(path, net.ListenUnix)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	info, err := os.Lstat(path)
	if err != nil || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("published socket: %v, %v", info, err)
	}
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	connection.Close()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("socket remains: %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 0 {
		t.Fatalf("staging residue: %v, %v", entries, err)
	}
}

func TestControlSocketRejectsOccupiedPaths(t *testing.T) {
	for _, symlink := range []bool{false, true} {
		root := t.TempDir()
		path := filepath.Join(root, "control.sock")
		target := filepath.Join(root, "target")
		if err := os.WriteFile(target, []byte("preserve"), 0o600); err != nil {
			t.Fatal(err)
		}
		var err error
		if symlink {
			err = os.Symlink(target, path)
		} else {
			err = os.WriteFile(path, []byte("preserve"), 0o600)
		}
		if err != nil {
			t.Fatal(err)
		}
		if listener, err := listenControlSocket(path, net.ListenUnix); err == nil {
			listener.Close()
			t.Fatal("occupied control path replaced")
		}
	}
}

func TestControlSocketRejectsForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a foreign-owned socket")
	}
	path := filepath.Join(t.TempDir(), "control.sock")
	existing, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer existing.Close()
	if err := os.Chown(path, 65534, -1); err != nil {
		t.Fatal(err)
	}
	if listener, err := listenControlSocket(path, net.ListenUnix); err == nil {
		listener.Close()
		t.Fatal("foreign socket replaced")
	}
	if _, err := os.Lstat(path); err != nil {
		t.Fatal("foreign socket removed", err)
	}
}

func TestControlSocketBindFailureCleansStage(t *testing.T) {
	root := t.TempDir()
	_, err := listenControlSocket(filepath.Join(root, "control.sock"), func(string, *net.UnixAddr) (*net.UnixListener, error) { return nil, os.ErrPermission })
	if err == nil {
		t.Fatal("bind failure lost")
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed bind residue: %v, %v", entries, err)
	}
}
