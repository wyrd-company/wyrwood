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
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		fmt.Println("open /proc/pid/mem:", err)
		return
	}
	buf := make([]byte, 16)
	_, err = f.ReadAt(buf, 0x400000)
	fmt.Println("read /proc/pid/mem:", err)
	_, err = os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	fmt.Println("read /proc/pid/environ:", err)
}
