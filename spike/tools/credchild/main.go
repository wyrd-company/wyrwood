// credchild is throwaway spike code for task 847 finding 3/5.
//
// It is the allowlisted reader in the ancestor-tracing test: it reads the file
// named by argv[1] (a FUSE-served credential) fully into a heap buffer, holds a
// reference so it stays resident, prints how many bytes it loaded, then sleeps.
// Its ancestor then scans its memory for the real credential.
package main

import (
	"fmt"
	"io"
	"os"
	"time"
)

var (
	held []byte   // package-level so the buffer is not garbage collected
	hold *os.File // keep the fd OPEN so /proc/<pid>/fd/N points at the credential
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: credchild FILE")
		os.Exit(2)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "open:", err)
		os.Exit(1)
	}
	hold = f
	b, err := io.ReadAll(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read:", err)
		os.Exit(1)
	}
	held = b
	fmt.Printf("loaded %d bytes, resident, fd held open\n", len(held))
	time.Sleep(300 * time.Second)
}
