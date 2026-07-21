// ---
// relationships:
//   implements: per-user-agent-proxy
// ---

package main

import (
	"os"

	"github.com/wyrd-company/wyrwood/internal/command"
)

func main() {
	os.Exit(command.Run(os.Args[1:], os.Stdout, os.Stderr))
}
