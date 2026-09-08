// Command tmpwriter rewrites a file the way gh and codex do: write a temp file
// in the same directory, then rename over the target.
package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: tmpwriter <target> <content>")
		os.Exit(2)
	}
	target, content := os.Args[1], os.Args[2]
	tmp := filepath.Join(filepath.Dir(target), ".tmp-"+filepath.Base(target))
	if err := os.WriteFile(tmp, []byte(content+"\n"), 0o600); err != nil {
		fmt.Println("write temp:", err)
		os.Exit(1)
	}
	if err := os.Rename(tmp, target); err != nil {
		fmt.Println("rename:", err)
		os.Remove(tmp)
		os.Exit(1)
	}
	fmt.Println("renamed ok")
}
