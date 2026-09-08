// Command ptracetest tries PTRACE_ATTACH and /proc/<pid>/mem on a same-UID,
// non-descendant process. Prints the outcome of each.
package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

func main() {
	pid, _ := strconv.Atoi(os.Args[1])
	err := syscall.PtraceAttach(pid)
	if err == nil {
		fmt.Println("PTRACE_ATTACH: succeeded")
		syscall.PtraceDetach(pid)
	} else {
		fmt.Println("PTRACE_ATTACH:", err)
	}
	if f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid)); err != nil {
		fmt.Println("open /proc/pid/mem:", err)
	} else {
		buf := make([]byte, 16)
		_, rerr := f.ReadAt(buf, 0x400000)
		fmt.Println("read /proc/pid/mem:", rerr)
		f.Close()
	}
	// Tested independently of the mem outcome (round 2, finding 3).
	_, eerr := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	fmt.Println("read /proc/pid/environ:", eerr)
	if ents, ferr := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid)); ferr != nil {
		fmt.Println("list /proc/pid/fd:", ferr)
	} else {
		fmt.Println("list /proc/pid/fd: succeeded, entries =", len(ents))
	}
}
