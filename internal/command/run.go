// ---
// relationships:
//   implements: command-line-interface
//   uses: control-interface
// ---

// Package command owns top-level command dispatch for the wyrwood executable.
package command

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/signal"
	"syscall"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/control"
	"github.com/wyrd-company/wyrwood/internal/daemon"
	"github.com/wyrd-company/wyrwood/internal/userservice"
)

const help = `Wyrwood provides stable, filtered SSH-agent endpoints for containers.

Usage:
  wyrwood <command> [options]

Commands:
  daemon    Run the per-user daemon
  init      Create the initial per-user configuration
  apply     Validate and apply the default configuration
  keys      List identities available from the upstream agent
  status    Inspect daemon and consumer health
  events    Inspect bounded operational events
  tui       Open the terminal user interface (not implemented)
  service   Manage per-user login startup
  version   Print version information
  help      Show this help

Management options:
  --output human|json   Select human output (default) or structured JSON
  --limit NUMBER        Events to return, from 1 through 1000 (default 100)
`

type controlClient interface {
	Apply() (control.ApplyResult, error)
	Keys() (control.KeysResult, error)
	Status() (control.StatusResult, error)
	Events(limit int) (control.EventsResult, error)
}

type dependencies struct {
	initialize         func() (string, error)
	defaultControlPath func() (string, error)
	newClient          func(string) (controlClient, error)
	runDaemon          func(context.Context, daemon.Options) error
	defaultDaemon      func() (daemon.Options, error)
	manageService      func(userservice.Action) (userservice.Result, error)
}

func defaultDependencies() dependencies {
	return dependencies{
		initialize:         config.Initialize,
		defaultControlPath: daemon.DefaultControlPath,
		newClient: func(path string) (controlClient, error) {
			return control.NewClient(path)
		},
		runDaemon:     daemon.Run,
		defaultDaemon: daemon.DefaultOptions,
		manageService: userservice.Manage,
	}
}

// Run executes the root command and returns a stable process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	return run(args, stdout, stderr, defaultDependencies())
}

func run(args []string, stdout, stderr io.Writer, deps dependencies) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stdout, help)
		return exitSuccess
	}

	switch args[0] {
	case "help", "-h", "--help":
		_, _ = io.WriteString(stdout, help)
		return exitSuccess
	case "version", "--version":
		_, _ = fmt.Fprintln(stdout, "wyrwood dev")
		return exitSuccess
	case "daemon":
		if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
			_, _ = io.WriteString(stdout, "Usage: wyrwood daemon\n")
			return exitSuccess
		}
		if len(args) != 1 {
			return writeFailure(stderr, outputHuman, "daemon", failureUsage)
		}
		return runDaemon(stdout, stderr, deps)
	case "init":
		return runInit(args[1:], stdout, stderr, deps)
	case "apply", "keys", "status", "events":
		return runManagement(args[0], args[1:], stdout, stderr, deps)
	case "service":
		return runService(args[1:], stdout, stderr, deps)
	case "tui":
		_, _ = fmt.Fprintf(stderr, "wyrwood %s is not implemented yet\n", args[0])
		return exitOperational
	default:
		_, _ = fmt.Fprintln(stderr, "unknown command")
		_, _ = fmt.Fprintln(stderr, "Run 'wyrwood help' for usage.")
		return exitUsage
	}
}

func runService(args []string, stdout, stderr io.Writer, deps dependencies) int {
	format := requestedOutput(args)
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		_, _ = io.WriteString(stdout, commandHelp("service"))
		return exitSuccess
	}
	if len(args) == 0 {
		return writeFailure(stderr, format, "service", failureUsage)
	}
	action := userservice.Action(args[0])
	switch action {
	case userservice.ActionInstall, userservice.ActionRemove, userservice.ActionStart, userservice.ActionStop, userservice.ActionStatus:
	default:
		return writeFailure(stderr, format, "service", failureUsage)
	}
	options, parseFailure, showHelp := parseCommandOptions("service", args[1:])
	if showHelp {
		_, _ = io.WriteString(stdout, commandHelp("service"))
		return exitSuccess
	}
	if parseFailure != nil {
		return writeFailure(stderr, options.output, "service", *parseFailure)
	}
	result, err := deps.manageService(action)
	if err != nil {
		problem := failureService
		switch {
		case errors.Is(err, userservice.ErrUnavailable):
			problem = failureServiceUnavailable
		case errors.Is(err, userservice.ErrNotInstalled):
			problem = failureServiceNotInstalled
		}
		return writeFailure(stderr, options.output, "service", problem)
	}
	return writeSuccess(stdout, stderr, options.output, "service", result)
}

func runDaemon(_ io.Writer, stderr io.Writer, deps dependencies) int {
	options, err := deps.defaultDaemon()
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "wyrwood daemon: could not resolve per-user paths")
		return exitOperational
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := deps.runDaemon(ctx, options); err != nil {
		_, _ = fmt.Fprintln(stderr, "wyrwood daemon: stopped with an operational error")
		return exitOperational
	}
	return exitSuccess
}

func runInit(args []string, stdout, stderr io.Writer, deps dependencies) int {
	options, parseFailure, showHelp := parseCommandOptions("init", args)
	if showHelp {
		_, _ = io.WriteString(stdout, commandHelp("init"))
		return exitSuccess
	}
	if parseFailure != nil {
		return writeFailure(stderr, options.output, "init", *parseFailure)
	}
	path, err := deps.initialize()
	if err != nil {
		var durability *config.DurabilityError
		if errors.As(err, &durability) {
			return writeFailure(stderr, options.output, "init", failureDurability)
		}
		return writeFailure(stderr, options.output, "init", failureInitialize)
	}
	return writeSuccess(stdout, stderr, options.output, "init", initResult{Path: path})
}

func runManagement(command string, args []string, stdout, stderr io.Writer, deps dependencies) int {
	options, parseFailure, showHelp := parseCommandOptions(command, args)
	if showHelp {
		_, _ = io.WriteString(stdout, commandHelp(command))
		return exitSuccess
	}
	if parseFailure != nil {
		return writeFailure(stderr, options.output, command, *parseFailure)
	}
	path, err := deps.defaultControlPath()
	if err != nil {
		return writeFailure(stderr, options.output, command, failureDaemonUnavailable)
	}
	client, err := deps.newClient(path)
	if err != nil {
		return writeFailure(stderr, options.output, command, failureDaemonUnavailable)
	}

	var result any
	switch command {
	case "apply":
		applied, requestErr := client.Apply()
		if requestErr == nil && !applied.Committed {
			requestErr = errUncommittedApply
		}
		result, err = applied, requestErr
	case "keys":
		result, err = client.Keys()
	case "status":
		result, err = client.Status()
	case "events":
		result, err = client.Events(options.eventLimit)
	}
	if err != nil {
		return writeFailure(stderr, options.output, command, classifyRequestFailure(err))
	}
	return writeSuccess(stdout, stderr, options.output, command, result)
}

var errUncommittedApply = errors.New("daemon did not commit configuration")
