// ---
// relationships:
//   implements: command-line-interface
//   uses: agent
// ---

package command

import (
	"context"
	"io"
	"os/signal"
	"syscall"
)

func runAgent(args []string, stdin io.Reader, stdout, stderr io.Writer, deps dependencies) int {
	if len(args) == 0 {
		return writeFailure(stderr, outputHuman, "agent", failureUsage)
	}
	name := "agent " + args[0]
	switch args[0] {
	case "daemon":
		options, positional, problem := parseOptions(args[1:], 0)
		if options.help {
			_, _ = io.WriteString(stdout, "Usage: wyrwood agent daemon\n")
			return exitSuccess
		}
		if problem != nil || len(positional) != 0 {
			return writeFailure(stderr, outputHuman, name, failureUsage)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := deps.runAgent(ctx); err != nil {
			return writeFailure(stderr, outputHuman, name, failureOperational)
		}
		return exitSuccess
	default:
		return writeFailure(stderr, outputHuman, "agent", failureUsage)
	}
}
