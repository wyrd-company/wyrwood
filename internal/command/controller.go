// ---
// relationships:
//   implements: command-line-interface
//   uses: controller
// ---

package command

import (
	"context"
	"fmt"
	"io"
	"os/signal"
	"syscall"
)

const defaultControllerConfig = "/etc/wyrwood/controller.yml"

func runController(args []string, stdout, stderr io.Writer, deps dependencies) int {
	if len(args) == 0 {
		return writeFailure(stderr, outputHuman, "controller", failureUsage)
	}
	name := "controller " + args[0]
	switch args[0] {
	case "serve":
		options, positional, problem := parseOptions(args[1:], optionConfig)
		if options.help {
			_, _ = io.WriteString(stdout, "Usage: wyrwood controller serve [--config PATH]\n")
			return exitSuccess
		}
		if problem != nil || len(positional) != 0 {
			return writeFailure(stderr, options.output, name, failureUsage)
		}
		ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()
		if err := deps.serveController(ctx, configPath(options)); err != nil {
			return writeFailure(stderr, options.output, name, controllerFailure(err))
		}
		return exitSuccess
	case "host-key":
		options, positional, problem := parseOptions(args[1:], optionConfig|optionOutput)
		if options.help {
			_, _ = io.WriteString(stdout, "Usage: wyrwood controller host-key [--config PATH] [--output human|json]\n")
			return exitSuccess
		}
		if problem != nil || len(positional) != 0 {
			return writeFailure(stderr, options.output, name, failureUsage)
		}
		fingerprint, err := deps.controllerHostKey(configPath(options))
		if err != nil {
			return writeFailure(stderr, options.output, name, controllerFailure(err))
		}
		if options.output == outputJSON {
			return writeJSON(stdout, struct {
				Version     int    `json:"version"`
				Fingerprint string `json:"fingerprint"`
			}{outputVersion, fingerprint})
		}
		_, _ = fmt.Fprintln(stdout, fingerprint)
		return exitSuccess
	default:
		return writeFailure(stderr, outputHuman, "controller", failureUsage)
	}
}

func configPath(options options) string {
	if options.config != "" {
		return options.config
	}
	return defaultControllerConfig
}

func controllerFailure(err error) failure {
	return failureOperational
}
