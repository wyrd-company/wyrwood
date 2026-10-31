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
	"github.com/wyrd-company/wyrwood/internal/engineproxy"
	"github.com/wyrd-company/wyrwood/internal/linuxservice"
	"github.com/wyrd-company/wyrwood/internal/web"
)

// errUnavailable marks a command whose implementation is not linked into this build.
var errUnavailable = errors.New("command unavailable")

// errConfiguration marks an invalid or unreadable configuration document.
var errConfiguration = errors.New("configuration unavailable")

type dependencies struct {
	serveController   func(ctx context.Context, configPath string) error
	controllerHostKey func(configPath string) (string, error)
	runAgent          func(ctx context.Context) error
	runEngineProxy    func(ctx context.Context, path string) error
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
		runEngineProxy:    func(ctx context.Context, path string) error { return engineproxy.Run(ctx, path, os.Stderr) },
		agentLogin: func(ctx context.Context, options agent.LoginOptions) (agent.LoginResult, error) {
			options.Paths = paths
			return agent.Login(ctx, options)
		},
		queryAgent: func(ctx context.Context, request agent.ControlRequest, destination any) error {
			return agent.Query(ctx, paths, request, destination)
		},
		manageService: func(action string) (string, error) {
			manager, err := linuxservice.NewManager()
			if err != nil {
				return "", err
			}
			state, err := manager.Manage(action)
			return string(state), err
		},
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
	operators, err := web.New(instance, web.Options{Version: version})
	if err != nil {
		return err
	}
	return runControllerServices(ctx, configuration.LocalAgent,
		func(ctx context.Context) error { return instance.Run(ctx, operators.Serve) },
		func(ctx context.Context) error { return runAgentDaemon(ctx, agent.DefaultPaths()) })
}

func controllerHostKey(path string) (string, error) {
	configuration, err := config.LoadController(path)
	if err != nil {
		return "", errConfiguration
	}
	return controller.HostKeyFingerprint(configuration.StateDirectory)
}

// runControllerServices owns both lifetimes. A startup or runtime failure in
// either service stops its peer before the controller state is closed.
func runControllerServices(ctx context.Context, localAgent bool, serve, runAgent func(context.Context) error) error {
	if !localAgent {
		return serve(ctx)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 2)
	go func() { done <- serve(ctx) }()
	go func() { done <- runAgent(ctx) }()
	first := <-done
	cancel()
	return errors.Join(first, <-done)
}

func runAgentDaemon(ctx context.Context, paths agent.Paths) error {
	err := agent.RunDaemon(ctx, paths, version, os.Stderr)
	if errors.Is(err, agent.ErrConfiguration) {
		return errConfiguration
	}
	return err
}
