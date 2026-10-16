// ---
// relationships:
//   implements: configuration
//   uses: agent
// ---

package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Agent defaults.
const (
	DefaultEngineSocket      = "/var/run/docker.sock"
	DefaultEngineProxySocket = "/run/wyrwood-engine/engine.sock"
	DefaultConsumerRoot      = "/run/wyrwood/containers"
	DefaultControllerPort    = "22"
	defaultEngineTimeout     = 10 * time.Second
	defaultControllerTimeout = 10 * time.Second
	defaultOpenBaoTimeout    = 10 * time.Second
	defaultSignTimeout       = 30 * time.Second
	minimumTimeout           = 100 * time.Millisecond
	maximumTimeout           = 30 * time.Second
	maximumSignTimeout       = 2 * time.Minute
)

// Agent is the validated agent configuration.
type Agent struct {
	ControllerURL     string
	ControllerAddress string
	EngineSocket      string
	EngineProxySocket string
	AllowRecreate     bool
	ConsumerRoot      string
	EngineTimeout     time.Duration
	ControllerTimeout time.Duration
	OpenBaoTimeout    time.Duration
	SignTimeout       time.Duration
}

type agentDocument struct {
	Controller *struct {
		URL string `yaml:"url"`
	} `yaml:"controller"`
	Engine *struct {
		Socket        *string `yaml:"socket"`
		ProxySocket   *string `yaml:"proxy-socket"`
		AllowRecreate *bool   `yaml:"allow-recreate"`
	} `yaml:"engine"`
	Consumers *struct {
		Root *string `yaml:"root"`
	} `yaml:"consumers"`
	Timeouts *struct {
		Engine     *string `yaml:"engine"`
		Controller *string `yaml:"controller"`
		OpenBao    *string `yaml:"openbao"`
		Sign       *string `yaml:"sign"`
	} `yaml:"timeouts"`
}

// LoadAgent reads and validates the agent configuration at path.
func LoadAgent(path string) (Agent, error) {
	data, err := readBounded(path, MaximumDocumentBytes)
	if err != nil {
		return Agent{}, err
	}
	return ParseAgent(data)
}

// ParseAgent validates one agent configuration document.
func ParseAgent(data []byte) (Agent, error) {
	var document agentDocument
	if err := decodeStrict(data, &document); err != nil {
		return Agent{}, err
	}
	if document.Controller == nil {
		return Agent{}, invalid("controller is required")
	}
	address, err := ControllerAddress(document.Controller.URL)
	if err != nil {
		return Agent{}, err
	}
	result := Agent{
		ControllerURL:     document.Controller.URL,
		ControllerAddress: address,
		EngineSocket:      DefaultEngineSocket,
		EngineProxySocket: DefaultEngineProxySocket,
		ConsumerRoot:      DefaultConsumerRoot,
		EngineTimeout:     defaultEngineTimeout,
		ControllerTimeout: defaultControllerTimeout,
		OpenBaoTimeout:    defaultOpenBaoTimeout,
		SignTimeout:       defaultSignTimeout,
	}
	if document.Engine != nil {
		if document.Engine.Socket != nil {
			if result.EngineSocket, err = canonicalPath("engine.socket", *document.Engine.Socket); err != nil {
				return Agent{}, err
			}
		}
		if document.Engine.ProxySocket != nil {
			if result.EngineProxySocket, err = canonicalPath("engine.proxy-socket", *document.Engine.ProxySocket); err != nil {
				return Agent{}, err
			}
		}
		if result.EngineSocket == result.EngineProxySocket {
			return Agent{}, invalid("engine sockets must differ")
		}
		if document.Engine.AllowRecreate != nil {
			result.AllowRecreate = *document.Engine.AllowRecreate
		}
	}
	if document.Consumers != nil && document.Consumers.Root != nil {
		if result.ConsumerRoot, err = canonicalPath("consumers.root", *document.Consumers.Root); err != nil {
			return Agent{}, err
		}
	}
	if timeouts := document.Timeouts; timeouts != nil {
		for _, field := range []struct {
			name    string
			value   *string
			target  *time.Duration
			maximum time.Duration
		}{
			{"timeouts.engine", timeouts.Engine, &result.EngineTimeout, maximumTimeout},
			{"timeouts.controller", timeouts.Controller, &result.ControllerTimeout, maximumTimeout},
			{"timeouts.openbao", timeouts.OpenBao, &result.OpenBaoTimeout, maximumTimeout},
			{"timeouts.sign", timeouts.Sign, &result.SignTimeout, maximumSignTimeout},
		} {
			if field.value == nil {
				continue
			}
			if !durationPattern.MatchString(*field.value) {
				return Agent{}, invalid("%s must be a whole number of ms, s, or m", field.name)
			}
			if *field.target, err = parseBoundedDuration(field.name, *field.value, minimumTimeout, field.maximum); err != nil {
				return Agent{}, err
			}
		}
	}
	return result, nil
}

// ControllerAddress validates a controller URL and returns its dial address.
func ControllerAddress(value string) (string, error) {
	if !controllerURLPattern.MatchString(value) {
		return "", invalid("controller URL must be ssh://host[:port]")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return "", invalid("controller URL must be ssh://host[:port]")
	}
	port := parsed.Port()
	if port == "" {
		port = DefaultControllerPort
	}
	return net.JoinHostPort(parsed.Hostname(), port), nil
}

// WriteAgentControllerURL records the controller URL in the agent
// configuration at path, creating a minimal document when none exists and
// otherwise changing only controller.url so comments and other fields remain.
func WriteAgentControllerURL(path, controllerURL string) error {
	if _, err := ControllerAddress(controllerURL); err != nil {
		return err
	}
	var root yaml.Node
	data, err := readBounded(path, MaximumDocumentBytes)
	switch {
	case os.IsNotExist(err):
		data = nil
	case err != nil:
		return err
	}
	if len(data) > 0 {
		if err := yaml.Unmarshal(data, &root); err != nil {
			return invalid("%v", err)
		}
	}
	if root.Kind == 0 {
		root = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode}}}
	}
	if root.Kind != yaml.DocumentNode || len(root.Content) != 1 || root.Content[0].Kind != yaml.MappingNode {
		return invalid("agent configuration must be a mapping")
	}
	controller := mappingValue(root.Content[0], "controller")
	if controller.Kind != yaml.MappingNode {
		*controller = yaml.Node{Kind: yaml.MappingNode}
	}
	urlNode := mappingValue(controller, "url")
	*urlNode = yaml.Node{Kind: yaml.ScalarNode, Value: controllerURL}
	encoded, err := yaml.Marshal(&root)
	if err != nil {
		return err
	}
	if _, err := ParseAgent(encoded); err != nil {
		return err
	}
	return writeFileAtomic(path, encoded, 0o644)
}

func mappingValue(mapping *yaml.Node, key string) *yaml.Node {
	for index := 0; index+1 < len(mapping.Content); index += 2 {
		if mapping.Content[index].Value == key {
			return mapping.Content[index+1]
		}
	}
	keyNode := &yaml.Node{Kind: yaml.ScalarNode, Value: key}
	valueNode := &yaml.Node{Kind: yaml.MappingNode}
	mapping.Content = append(mapping.Content, keyNode, valueNode)
	return valueNode
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".wyrwood-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chmod(mode); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("replace configuration: %w", err)
	}
	return nil
}
