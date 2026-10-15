// ---
// relationships:
//   verifies: agent
// ---

package consumer

import (
	"net"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestDirectoryModesAndSocketReplacement(t *testing.T) {
	root, err := OpenRoot(filepath.Join(t.TempDir(), "containers"))
	if err != nil {
		t.Fatal(err)
	}
	directory, err := root.Open("web", nil)
	if err != nil {
		t.Fatal(err)
	}
	assertMode(t, directory.Path(), 0o700)
	listener, err := directory.Listen(VaultSocket)
	if err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(directory.Path(), VaultSocket)
	assertMode(t, socketPath, 0o600)
	firstInode := inode(t, directory.Path())

	replacement, err := directory.Listen(VaultSocket)
	if err != nil {
		t.Fatalf("replacing socket = %v", err)
	}
	_ = listener.Close()
	go func() {
		connection, err := replacement.Accept()
		if err == nil {
			_, _ = connection.Write([]byte("ok"))
			_ = connection.Close()
		}
	}()
	connection, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial replaced socket = %v", err)
	}
	buffer := make([]byte, 2)
	if _, err := connection.Read(buffer); err != nil || string(buffer) != "ok" {
		t.Fatalf("read = %q, %v", buffer, err)
	}
	_ = connection.Close()
	if inode(t, directory.Path()) != firstInode {
		t.Fatal("directory was replaced")
	}

	group := uint32(os.Getegid())
	if err := directory.SetGroup(&group); err != nil {
		t.Fatal(err)
	}
	assertMode(t, directory.Path(), 0o750)
	assertMode(t, socketPath, 0o660)

	_ = replacement.Close()
	if err := directory.RemoveSockets(); err != nil {
		t.Fatal(err)
	}
	if inode(t, directory.Path()) != firstInode {
		t.Fatal("socket cleanup removed or replaced the directory")
	}
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		t.Fatalf("socket still present: %v", err)
	}
	_ = directory.Close()
}

func TestRemoveSocketsDoesNotFollowARenamedDirectory(t *testing.T) {
	base := t.TempDir()
	root, err := OpenRoot(filepath.Join(base, "containers"))
	if err != nil {
		t.Fatal(err)
	}
	directory, err := root.Open("web", nil)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := directory.Listen(SSHAgentSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	defer directory.Close()
	moved := filepath.Join(base, "moved")
	if err := os.Rename(directory.Path(), moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory.Path(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory.Path(), "keep"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := directory.RemoveSockets(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(directory.Path(), "keep")); err != nil {
		t.Fatalf("cleanup touched the replacement directory: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(moved, SSHAgentSocket)); !os.IsNotExist(err) {
		t.Fatalf("socket in the pinned directory was not removed: %v", err)
	}
}

func TestInvalidNamesAndNonSocketOccupants(t *testing.T) {
	root, err := OpenRoot(filepath.Join(t.TempDir(), "containers"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "..", "a/b", "-x", ".hidden"} {
		if _, err := root.Open(name, nil); err == nil {
			t.Errorf("Open(%q) = nil", name)
		}
	}
	directory, err := root.Open("web", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	if err := os.WriteFile(filepath.Join(directory.Path(), VaultSocket), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := directory.Listen(VaultSocket); err == nil {
		t.Fatal("Listen replaced a regular file")
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != want {
		t.Fatalf("%s mode = %v, want %v", filepath.Base(path), info.Mode().Perm(), want)
	}
}

func inode(t *testing.T, path string) uint64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Sys().(*syscall.Stat_t).Ino
}

func TestRemoveSocketsRejectsNonSocketOccupants(t *testing.T) {
	root, err := OpenRoot(filepath.Join(t.TempDir(), "containers"))
	if err != nil {
		t.Fatal(err)
	}
	directory, err := root.Open("app", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	path := filepath.Join(directory.Path(), VaultSocket)
	if err := os.WriteFile(path, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := directory.Listen(SSHAgentSocket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := directory.RemoveSockets(); err == nil {
		t.Fatal("cleanup accepted a non-socket occupant")
	}
	if data, err := os.ReadFile(path); err != nil || string(data) != "keep" {
		t.Fatalf("cleanup changed non-socket file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory.Path(), SSHAgentSocket)); !os.IsNotExist(err) {
		t.Fatalf("other socket was not removed after cleanup error: %v", err)
	}
}
