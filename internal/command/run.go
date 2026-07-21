// ---
// relationships: {}
// ---

// Package command owns top-level command dispatch for the wyrwood executable.
package command

import (
	"fmt"
	"io"
)

const help = `Wyrwood provides stable, filtered SSH-agent endpoints for containers.

Usage:
  wyrwood <command>

Commands:
  daemon    Run the per-user daemon
  init      Create the initial per-user configuration
  apply     Validate and apply configuration
  keys      List identities available from the upstream agent
  status    Inspect daemon and consumer health
  events    Inspect bounded operational events
  tui       Open the terminal user interface
  service   Manage per-user login startup
  version   Print version information
  help      Show this help
`

// Run executes the root command and returns a process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stdout, help)
		return 0
	}

	switch args[0] {
	case "help", "-h", "--help":
		_, _ = io.WriteString(stdout, help)
		return 0
	case "version", "--version":
		_, _ = fmt.Fprintln(stdout, "wyrwood dev")
		return 0
	case "daemon", "init", "apply", "keys", "status", "events", "tui", "service":
		_, _ = fmt.Fprintf(stderr, "wyrwood %s is not implemented yet\n", args[0])
		return 1
	default:
		_, _ = fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		_, _ = fmt.Fprintln(stderr, "Run 'wyrwood help' for usage.")
		return 2
	}
}
