// ---
// relationships:
//   implements: command-line-interface
// ---

package command

import (
	"context"
	"errors"
	"os"

	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/controller"
)

// errUnavailable marks a command whose implementation is not linked into this build.
var errUnavailable = errors.New("command unavailable")

// errConfiguration marks an invalid or unreadable configuration document.
var errConfiguration = errors.New("configuration unavailable")

type dependencies struct {
	serveController   func(ctx context.Context, configPath string) error
	controllerHostKey func(configPath string) (string, error)
	runAgent          func(ctx context.Context) error
}

func defaultDependencies() dependencies {
	return dependencies{
		serveController:   serveController,
		controllerHostKey: controllerHostKey,
		runAgent:          func(context.Context) error { return errUnavailable },
	}
}

func serveController(ctx context.Context, path string) error {
	configuration, err := config.LoadController(path)
	if err != nil {
		return errConfiguration
	}
	instance, err := controller.New(configuration, controller.Options{Log: os.Stderr})
	if err != nil {
		return err
	}
	defer instance.Close()
	return instance.Run(ctx, nil)
}

func controllerHostKey(path string) (string, error) {
	configuration, err := config.LoadController(path)
	if err != nil {
		return "", errConfiguration
	}
	return controller.HostKeyFingerprint(configuration.StateDirectory)
}
