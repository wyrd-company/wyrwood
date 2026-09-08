// Command ancestorptrace spawns a child and, as its ancestor, tries
// PTRACE_ATTACH, /proc/<pid>/mem, /proc/<pid>/environ, and process_vm_readv.
// Yama ptrace_scope=1 permits ancestors; this shows whether an attacker that
// launches an allowlisted CLI can read its memory.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

func firstMap(pid int) uintptr {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		fmt.Println("open maps:", err)
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		l := sc.Text()
		if strings.Contains(l, " r") {
			a, _ := strconv.ParseUint(strings.Split(strings.Fields(l)[0], "-")[0], 16, 64)
			return uintptr(a)
		}
	}
	return 0
}

func main() {
	cmd := exec.Command("sh", "-c", "SECRET_IN_ENV=canary-value-1234 exec sleep 30")
	if err := cmd.Start(); err != nil {
		panic(err)
	}
	pid := cmd.Process.Pid
	time.Sleep(200 * time.Millisecond)
	env, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	fmt.Println("read child environ:", err, "contains canary:", strings.Contains(string(env), "canary-value-1234"))
	addr := firstMap(pid)
	buf := make([]byte, 16)
	if f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid)); err == nil {
		_, rerr := f.ReadAt(buf, int64(addr))
		fmt.Println("read child /proc/pid/mem:", rerr)
		f.Close()
	} else {
		fmt.Println("open child /proc/pid/mem:", err)
	}
	local := syscall.Iovec{Base: &buf[0], Len: 16}
	remote := syscall.Iovec{Base: (*byte)(unsafe.Pointer(addr)), Len: 16}
	const sysProcessVMReadv = 310 // linux/amd64
	n, _, errno := syscall.Syscall6(sysProcessVMReadv, uintptr(pid), uintptr(unsafe.Pointer(&local)), 1, uintptr(unsafe.Pointer(&remote)), 1, 0)
	fmt.Println("process_vm_readv on child: n =", int(n), "errno =", errno)
	err = syscall.PtraceAttach(pid)
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
