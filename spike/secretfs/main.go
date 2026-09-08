// Command secretfs is throwaway spike code for kanban task 847.
//
// It serves a backing directory through FUSE. Requesters in the daemon's own
// mount namespace (host processes) and container requesters whose
// /proc/<pid>/exe resolves to an allowlisted executable read real bytes and
// may write. Every other requester reads a redacted copy and cannot write.
//
// Every open records the requester identity it could observe so the spike can
// answer the identity questions from real evidence.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
)

var secretField = regexp.MustCompile(`(?i)("?(?:[a-z_]*(?:token|secret|password|api[_-]?key)[a-z_]*)"?\s*[:=]\s*)("[^"]*"|[^\s,}]+)`)

func redact(b []byte) []byte {
	return secretField.ReplaceAllFunc(b, func(m []byte) []byte {
		sub := secretField.FindSubmatch(m)
		val := sub[2]
		if len(val) > 0 && val[0] == '"' {
			return append(append([]byte{}, sub[1]...), []byte(`"REDACTED"`)...)
		}
		return append(append([]byte{}, sub[1]...), []byte("REDACTED")...)
	})
}

type identity struct {
	Time     string `json:"time"`
	Op       string `json:"op"`
	Path     string `json:"path"`
	Pid      uint32 `json:"pid"`
	Uid      uint32 `json:"uid"`
	Gid      uint32 `json:"gid"`
	Exe      string `json:"exe"`
	ExeDev   uint64 `json:"exe_dev"`
	ExeIno   uint64 `json:"exe_ino"`
	ExeHash  string `json:"exe_sha256,omitempty"`
	Cmdline  string `json:"cmdline"`
	Comm     string `json:"comm"`
	MntNS    string `json:"mnt_ns"`
	PidNS    string `json:"pid_ns"`
	Origin   string `json:"origin"` // host | container | unknown
	Decision string `json:"decision"`
	Err      string `json:"err,omitempty"`
}

type policy struct {
	selfMntNS string
	allow     map[string]bool // by exe path (host view)
	allowHash map[string]bool // by sha256
	hashExe   bool
	logMu     sync.Mutex
	logW      io.Writer
}

func readlink(p string) string {
	s, err := os.Readlink(p)
	if err != nil {
		return "ERR:" + err.Error()
	}
	return s
}

func (p *policy) identify(ctx context.Context, op, path string) identity {
	id := identity{Time: time.Now().Format(time.RFC3339Nano), Op: op, Path: path}
	c, ok := fuse.FromContext(ctx)
	if !ok || c.Pid == 0 {
		id.Origin = "unknown"
		id.Decision = "redacted"
		id.Err = "no caller pid"
		return id
	}
	id.Pid, id.Uid, id.Gid = c.Pid, c.Uid, c.Gid
	proc := fmt.Sprintf("/proc/%d", c.Pid)
	id.Exe = readlink(proc + "/exe")
	id.MntNS = readlink(proc + "/ns/mnt")
	id.PidNS = readlink(proc + "/ns/pid")
	if b, err := os.ReadFile(proc + "/cmdline"); err == nil {
		id.Cmdline = strings.ReplaceAll(strings.TrimRight(string(b), "\x00"), "\x00", " ")
	}
	if b, err := os.ReadFile(proc + "/comm"); err == nil {
		id.Comm = strings.TrimSpace(string(b))
	}
	// Stat the exe through /proc/<pid>/exe so we get the container's inode, not a host path.
	var st syscall.Stat_t
	if err := syscall.Stat(proc+"/exe", &st); err == nil {
		id.ExeDev, id.ExeIno = uint64(st.Dev), st.Ino
	}
	if p.hashExe {
		if f, err := os.Open(proc + "/exe"); err == nil {
			h := sha256.New()
			io.Copy(h, f)
			f.Close()
			id.ExeHash = hex.EncodeToString(h.Sum(nil))
		}
	}
	if id.MntNS == p.selfMntNS {
		id.Origin = "host"
		id.Decision = "real"
		return id
	}
	id.Origin = "container"
	if p.allow[id.Exe] || (id.ExeHash != "" && p.allowHash[id.ExeHash]) {
		id.Decision = "real"
	} else {
		id.Decision = "redacted"
	}
	return id
}

func (p *policy) record(id identity) {
	b, _ := json.Marshal(id)
	p.logMu.Lock()
	defer p.logMu.Unlock()
	fmt.Fprintln(p.logW, string(b))
}

type node struct {
	fs.LoopbackNode
	pol *policy
}

func (n *node) check(ctx context.Context, op string, wantWrite bool) (identity, bool) {
	id := n.pol.identify(ctx, op, n.LoopbackNode.EmbeddedInode().Path(nil))
	allowed := id.Decision == "real"
	if wantWrite && !allowed {
		id.Decision = "denied"
	}
	n.pol.record(id)
	return id, allowed
}

// redactedFile is a read-only in-memory handle served with direct IO so the
// kernel page cache cannot leak real bytes between requesters.
type redactedFile struct{ data []byte }

func (f *redactedFile) Read(ctx context.Context, dest []byte, off int64) (fuse.ReadResult, syscall.Errno) {
	if off >= int64(len(f.data)) {
		return fuse.ReadResultData(nil), 0
	}
	end := off + int64(len(dest))
	if end > int64(len(f.data)) {
		end = int64(len(f.data))
	}
	return fuse.ReadResultData(f.data[off:end]), 0
}

func isWrite(flags uint32) bool {
	acc := flags & syscall.O_ACCMODE
	return acc == syscall.O_WRONLY || acc == syscall.O_RDWR || flags&syscall.O_TRUNC != 0
}

func (n *node) Open(ctx context.Context, flags uint32) (fs.FileHandle, uint32, syscall.Errno) {
	_, allowed := n.check(ctx, "open", isWrite(flags))
	if allowed {
		fh, fl, errno := n.LoopbackNode.Open(ctx, flags)
		return fh, fl | fuse.FOPEN_DIRECT_IO, errno
	}
	if isWrite(flags) {
		return nil, 0, syscall.EACCES
	}
	real, err := os.ReadFile(filepath.Join(n.RootData.Path, n.EmbeddedInode().Path(nil)))
	if err != nil {
		return nil, 0, fs.ToErrno(err)
	}
	return &redactedFile{data: redact(real)}, fuse.FOPEN_DIRECT_IO, 0
}

func (n *node) Getattr(ctx context.Context, f fs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	errno := n.LoopbackNode.Getattr(ctx, f, out)
	if errno != 0 {
		return errno
	}
	// Redacted readers must see the redacted size or short reads confuse them.
	if rf, ok := f.(*redactedFile); ok {
		out.Size = uint64(len(rf.data))
	} else if out.Mode&syscall.S_IFMT == syscall.S_IFREG {
		if id := n.pol.identify(ctx, "getattr", n.EmbeddedInode().Path(nil)); id.Decision != "real" {
			if real, err := os.ReadFile(filepath.Join(n.RootData.Path, n.EmbeddedInode().Path(nil))); err == nil {
				out.Size = uint64(len(redact(real)))
			}
		}
	}
	out.SetTimeout(0)
	return 0
}

func (n *node) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fs.Inode, fs.FileHandle, uint32, syscall.Errno) {
	if _, ok := n.check(ctx, "create:"+name, true); !ok {
		return nil, nil, 0, syscall.EACCES
	}
	in, fh, fl, errno := n.LoopbackNode.Create(ctx, name, flags, mode, out)
	return in, fh, fl | fuse.FOPEN_DIRECT_IO, errno
}

func (n *node) Rename(ctx context.Context, name string, newParent fs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if _, ok := n.check(ctx, "rename:"+name+"->"+newName, true); !ok {
		return syscall.EACCES
	}
	return n.LoopbackNode.Rename(ctx, name, newParent, newName, flags)
}

func (n *node) Unlink(ctx context.Context, name string) syscall.Errno {
	if _, ok := n.check(ctx, "unlink:"+name, true); !ok {
		return syscall.EACCES
	}
	return n.LoopbackNode.Unlink(ctx, name)
}

func (n *node) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fs.Inode, syscall.Errno) {
	if _, ok := n.check(ctx, "mkdir:"+name, true); !ok {
		return nil, syscall.EACCES
	}
	return n.LoopbackNode.Mkdir(ctx, name, mode, out)
}

func (n *node) Setattr(ctx context.Context, f fs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if _, ok := n.check(ctx, "setattr", true); !ok {
		return syscall.EACCES
	}
	return n.LoopbackNode.Setattr(ctx, f, in, out)
}

func main() {
	backing := flag.String("backing", "", "directory holding the real files")
	mount := flag.String("mount", "", "mountpoint, or /dev/fd/N to adopt an existing /dev/fuse fd")
	allow := flag.String("allow", "", "comma-separated exe paths (as seen in /proc/<pid>/exe) allowed real bytes from containers")
	allowHash := flag.String("allow-sha256", "", "comma-separated sha256 of executables allowed real bytes")
	logPath := flag.String("log", "", "identity log file (default stderr)")
	hashExe := flag.Bool("hash-exe", false, "hash /proc/<pid>/exe on every open")
	allowOther := flag.Bool("allow-other", false, "pass allow_other (needs user_allow_other in /etc/fuse.conf)")
	reexec := flag.Bool("reexec-on-usr1", false, "on SIGUSR1, re-exec self handing over the fuse fd (restart mitigation)")
	flag.Parse()
	if *backing == "" || *mount == "" {
		log.Fatal("need -backing and -mount")
	}
	pol := &policy{selfMntNS: readlink("/proc/self/ns/mnt"), allow: map[string]bool{}, allowHash: map[string]bool{}, hashExe: *hashExe, logW: os.Stderr}
	for _, a := range strings.Split(*allow, ",") {
		if a != "" {
			pol.allow[a] = true
		}
	}
	for _, a := range strings.Split(*allowHash, ",") {
		if a != "" {
			pol.allowHash[a] = true
		}
	}
	if *logPath != "" {
		f, err := os.OpenFile(*logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
		if err != nil {
			log.Fatal(err)
		}
		pol.logW = f
	}
	root := &fs.LoopbackRoot{Path: *backing}
	root.NewNode = func(rootData *fs.LoopbackRoot, parent *fs.Inode, name string, st *syscall.Stat_t) fs.InodeEmbedder {
		return &node{LoopbackNode: fs.LoopbackNode{RootData: rootData}, pol: pol}
	}
	rootNode := root.NewNode(root, nil, "", &syscall.Stat_t{})
	root.RootNode = rootNode
	zero := time.Duration(0)
	opts := &fs.Options{AttrTimeout: &zero, EntryTimeout: &zero}
	opts.MountOptions.AllowOther = *allowOther
	opts.MountOptions.Name = "secretfs"
	opts.MountOptions.FsName = "secretfs"
	opts.MountOptions.Options = []string{"default_permissions"}
	srv, err := fs.Mount(*mount, rootNode, opts)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("secretfs pid=%d mounted %s -> %s (self mnt ns %s)", os.Getpid(), *backing, *mount, pol.selfMntNS)

	if *reexec {
		go func() {
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGUSR1)
			<-ch
			// The /dev/fuse fd is CLOEXEC; dup it to a stable, inheritable fd 3.
			fd := serverFd(srv)
			if fd < 0 {
				log.Printf("reexec: cannot find fuse fd")
				return
			}
			args := []string{}
			for _, a := range os.Args[1:] {
				if strings.HasPrefix(a, "-mount") || strings.HasPrefix(a, "--mount") {
					continue
				}
				args = append(args, a)
			}
			args = append(args, "-mount=/dev/fd/3")
			cmd := exec.Command(os.Args[0], args...)
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			cmd.ExtraFiles = []*os.File{os.NewFile(uintptr(fd), "fuse")}
			if err := cmd.Start(); err != nil {
				log.Printf("reexec failed: %v", err)
				return
			}
			log.Printf("reexec: handed fuse fd to pid %d, old pid %d exiting without unmount", cmd.Process.Pid, os.Getpid())
			os.Exit(0)
		}()
	}
	srv.Wait()
}

// serverFd finds the /dev/fuse fd held by this process.
func serverFd(_ *fuse.Server) int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	for _, e := range entries {
		if readlink("/proc/self/fd/"+e.Name()) == "/dev/fuse" {
			var n int
			fmt.Sscanf(e.Name(), "%d", &n)
			return n
		}
	}
	return -1
}
