// ---
// relationships:
//   verifies: controller
// ---

package controller

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestHostKeyRepairsOwnedBrokenDirectory(t *testing.T) {
	for _, existingKey := range []bool{false, true} {
		state := t.TempDir()
		directory := filepath.Join(state, "ssh")
		var fingerprint string
		if existingKey {
			signer, err := LoadOrCreateHostKey(state)
			if err != nil {
				t.Fatal(err)
			}
			fingerprint = ssh.FingerprintSHA256(signer.PublicKey())
		} else if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o600); err != nil {
			t.Fatal(err)
		}
		signer, err := LoadOrCreateHostKey(state)
		if err != nil {
			t.Fatalf("restart with broken directory: %v", err)
		}
		info, err := os.Stat(directory)
		if err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("repaired directory: %v, %v", info, err)
		}
		if existingKey && fingerprint != ssh.FingerprintSHA256(signer.PublicKey()) {
			t.Fatal("recovery replaced host key")
		}
		again, err := LoadOrCreateHostKey(state)
		if err != nil || ssh.FingerprintSHA256(again.PublicKey()) != ssh.FingerprintSHA256(signer.PublicKey()) {
			t.Fatalf("second restart: %v", err)
		}
	}
}

func TestHostKeyRecoveryDoesNotChmodOtherPaths(t *testing.T) {
	for _, scenario := range []string{"symlink", "file", "other-mode", "unowned"} {
		t.Run(scenario, func(t *testing.T) {
			state := t.TempDir()
			directory := filepath.Join(state, "ssh")
			target := directory
			mode := os.FileMode(0o600)
			switch scenario {
			case "symlink":
				target = filepath.Join(state, "target")
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(target, mode); err != nil {
					t.Fatal(err)
				}
				defer os.Chmod(target, 0o700)
				if err := os.Symlink(target, directory); err != nil {
					t.Fatal(err)
				}
			case "file":
				if err := os.WriteFile(target, []byte("preserve"), mode); err != nil {
					t.Fatal(err)
				}
			default:
				if scenario == "unowned" && os.Geteuid() != 0 {
					t.Skip("requires root to create a foreign-owned directory")
				}
				if scenario == "other-mode" {
					mode = 0o500
				}
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(target, mode); err != nil {
					t.Fatal(err)
				}
				if scenario == "unowned" {
					if err := os.Chown(target, 65534, -1); err != nil {
						t.Fatal(err)
					}
				}
				defer os.Chmod(target, 0o700)
			}
			_, err := LoadOrCreateHostKey(state)
			if scenario != "other-mode" && err == nil {
				t.Fatal("unsafe directory accepted")
			}
			info, err := os.Lstat(target)
			if err != nil || info.Mode().Perm() != mode {
				t.Fatalf("unrelated path changed: %v, %v", info, err)
			}
		})
	}
}
