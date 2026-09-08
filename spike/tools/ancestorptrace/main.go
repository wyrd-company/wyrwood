// Command ancestorptrace launches a child (argv[1:], e.g. an allowlisted
// credchild reading a FUSE-served credential) and, as its ancestor under Yama
// ptrace_scope=1, tries to recover the credential from the child's address
// space: it scans readable memory regions for NEEDLE, reads /proc/<pid>/environ,
// and does PTRACE_ATTACH/GETREGS. This shows whether an attacker that launches
// an allowlisted CLI can read the plaintext it loaded.
package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func needle() []byte {
	n := os.Getenv("NEEDLE")
	if n == "" {
		n = "gho_FAKE"
	}
	return []byte(n)
}

// scanMem reads each readable region from /proc/pid/maps via /proc/pid/mem and
// reports whether the needle appears in the child's memory.
func scanMem(pid int, want []byte) bool {
	maps, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		fmt.Println("open maps:", err)
		return false
	}
	defer maps.Close()
	mem, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		fmt.Println("open mem:", err)
		return false
	}
	defer mem.Close()
	sc := bufio.NewScanner(maps)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 2 || !strings.HasPrefix(fields[1], "r") {
			continue
		}
		bounds := strings.Split(fields[0], "-")
		lo, _ := strconv.ParseUint(bounds[0], 16, 64)
		hi, _ := strconv.ParseUint(bounds[1], 16, 64)
		size := hi - lo
		if size == 0 || size > 8<<20 { // skip huge regions
			continue
		}
		buf := make([]byte, size)
		if _, err := mem.ReadAt(buf, int64(lo)); err != nil && err.Error() != "EOF" {
			continue
		}
		if bytes.Contains(buf, want) {
			return true
		}
	}
	return false
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"sh", "-c", "SECRET_IN_ENV=canary-1234 exec sleep 30"}
	}
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		panic(err)
	}
	pid := cmd.Process.Pid
	time.Sleep(500 * time.Millisecond) // let the child load the credential

	env, _ := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	fmt.Println("child environ contains canary-1234:", bytes.Contains(env, []byte("canary-1234")))

	found := scanMem(pid, needle())
	fmt.Printf("recovered credential from child memory (needle=%q): %v\n", string(needle()), found)

	err := syscall.PtraceAttach(pid)
	fmt.Println("PTRACE_ATTACH child:", err)
	if err == nil {
		var ws syscall.WaitStatus
		syscall.Wait4(pid, &ws, 0, nil)
		var regs syscall.PtraceRegs
		fmt.Println("PTRACE_GETREGS:", syscall.PtraceGetRegs(pid, &regs))
		syscall.PtraceDetach(pid)
	}
	cmd.Process.Kill()
}
