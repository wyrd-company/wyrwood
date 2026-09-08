// fdopener is throwaway spike code for task 847 finding 5.
//
// It opens the file named by argv[1] (this open() is charged to fdopener's
// identity), dups it to STDIN, then execs argv[2:] which reads stdin directly (no re-open). Used to
// show that an fd opened by an allowlisted binary keeps or loses real bytes
// when read by a non-allowlisted binary, depending on open- vs read-gating.
//
// With no argv[2], it reads fd itself and prints, as an allowlisted baseline.
package main

import (
	"fmt"
	"io"
	"os"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: fdopener FILE [EXEC ARGS...]")
		os.Exit(2)
	}
	flags := os.O_RDONLY
	if os.Getenv("RDWR") == "1" {
		flags = os.O_RDWR
	}
	f, err := os.OpenFile(os.Args[1], flags, 0)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	if len(os.Args) == 2 {
		b, _ := io.ReadAll(f)
		os.Stdout.Write(b)
		return
	}
	// Redirect stdin to the open file description so the child reads it
	// directly, without re-opening the path through FUSE.
	if err := syscall.Dup2(int(f.Fd()), 0); err != nil {
		fmt.Fprintln(os.Stderr, "dup2:", err)
		os.Exit(1)
	}
	if err := syscall.Exec(os.Args[2], os.Args[2:], os.Environ()); err != nil {
		fmt.Fprintln(os.Stderr, "exec:", err)
		os.Exit(1)
	}
}
