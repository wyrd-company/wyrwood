// ---
// relationships:
//   implements: command-line-interface
// ---

package command

import (
	"context"
	"errors"
	"os"

	"github.com/wyrd-company/wyrwood/internal/agent"
	"github.com/wyrd-company/wyrwood/internal/config"
	"github.com/wyrd-company/wyrwood/internal/controller"
	"github.com/wyrd-company/wyrwood/internal/engine"
)

// errUnavailable marks a command whose implementation is not linked into this build.
var errUnavailable = errors.New("command unavailable")

// errConfiguration marks an invalid or unreadable configuration document.
var errConfiguration = errors.New("configuration unavailable")

type dependencies struct {
	serveController   func(ctx context.Context, configPath string) error
	controllerHostKey func(configPath string) (string, error)
	runAgent          func(ctx context.Context) error
	agentLogin        func(ctx context.Context, options agent.LoginOptions) (agent.LoginResult, error)
	queryAgent        func(ctx context.Context, request agent.ControlRequest, destination any) error
	manageService     func(action string) (string, error)
}

func defaultDependencies() dependencies {
	paths := agent.DefaultPaths()
	return dependencies{
		serveController:   serveController,
		controllerHostKey: controllerHostKey,
		runAgent:          func(ctx context.Context) error { return runAgentDaemon(ctx, paths) },
		agentLogin: func(ctx context.Context, options agent.LoginOptions) (agent.LoginResult, error) {
			options.Paths = paths
			return agent.Login(ctx, options)
		},
		queryAgent: func(ctx context.Context, request agent.ControlRequest, destination any) error {
			return agent.Query(ctx, paths, request, destination)
		},
		manageService: func(string) (string, error) { return "", errUnavailable },
	}
}

func runAgentDaemon(ctx context.Context, paths agent.Paths) error {
	configuration, err := config.LoadAgent(paths.Config)
	if err != nil {
		return errConfiguration
	}
	agent.Version = version
	instance, err := agent.New(agent.Options{
		Config: configuration, Paths: paths, Engine: engine.NewClient(configuration.EngineSocket), Log: os.Stderr,
	})
	if err != nil {
		return err
	}
	return instance.Run(ctx)
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
