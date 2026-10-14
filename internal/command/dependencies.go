// ---
// relationships:
//   implements: command-line-interface
// ---

package command

import (
	"context"
	"errors"
)

// errUnavailable marks a command whose implementation is not linked into this build.
var errUnavailable = errors.New("command unavailable")

type dependencies struct {
	serveController   func(ctx context.Context, configPath string) error
	controllerHostKey func(configPath string) (string, error)
	runAgent          func(ctx context.Context) error
}

func defaultDependencies() dependencies {
	return dependencies{
		serveController:   func(context.Context, string) error { return errUnavailable },
		controllerHostKey: func(string) (string, error) { return "", errUnavailable },
		runAgent:          func(context.Context) error { return errUnavailable },
	}
}
