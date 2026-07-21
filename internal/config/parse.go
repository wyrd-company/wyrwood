// ---
// relationships: {}
// ---

package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

var (
	rootFields = map[string]struct{}{
		"upstream": {}, "consumers": {}, "timeouts": {},
	}
	consumerFields = map[string]struct{}{
		"name": {}, "socket": {}, "access-group": {}, "fingerprints": {},
	}
	timeoutFields = map[string]struct{}{
		"connect": {}, "list": {}, "replay": {}, "sign": {},
	}
)

// Parse decodes and validates one strict YAML configuration document.
func Parse(data []byte) (Config, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{}, fieldError("", "document is empty")
		}
		return Config{}, fmt.Errorf("parse configuration YAML: %w", err)
	}

	var extra yaml.Node
	if err := decoder.Decode(&extra); err == nil {
		return Config{}, fieldError("", "must contain exactly one YAML document")
	} else if !errors.Is(err, io.EOF) {
		return Config{}, fmt.Errorf("parse configuration YAML: %w", err)
	}
	if len(document.Content) != 1 {
		return Config{}, fieldError("", "document is empty")
	}

	locations := make(map[string]*yaml.Node)
	configValue, err := decodeConfig(document.Content[0], locations)
	if err != nil {
		return Config{}, err
	}
	if err := Validate(configValue); err != nil {
		return Config{}, addLocation(err, locations)
	}
	return configValue, nil
}

// Load reads and parses a configuration file.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read configuration %s: %w", path, err)
	}
	configuration, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("parse configuration %s: %w", path, err)
	}
	return configuration, nil
}

func decodeConfig(node *yaml.Node, locations map[string]*yaml.Node) (Config, error) {
	fields, err := mapping(node, "", rootFields, locations)
	if err != nil {
		return Config{}, err
	}
	for _, required := range []string{"upstream", "consumers", "timeouts"} {
		if err := requireField(fields, required, "", node); err != nil {
			return Config{}, err
		}
	}

	upstream, err := stringValue(fields["upstream"], "upstream")
	if err != nil {
		return Config{}, err
	}
	consumers, err := decodeConsumers(fields["consumers"], locations)
	if err != nil {
		return Config{}, err
	}
	timeouts, err := decodeTimeouts(fields["timeouts"], locations)
	if err != nil {
		return Config{}, err
	}
	return Config{Upstream: upstream, Consumers: consumers, Timeouts: timeouts}, nil
}

func decodeConsumers(node *yaml.Node, locations map[string]*yaml.Node) ([]Consumer, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, nodeError("consumers", node, "must be a sequence")
	}
	consumers := make([]Consumer, 0, len(node.Content))
	for index, item := range node.Content {
		path := fmt.Sprintf("consumers[%d]", index)
		locations[path] = item
		fields, err := mapping(item, path, consumerFields, locations)
		if err != nil {
			return nil, err
		}
		for _, required := range []string{"name", "socket", "fingerprints"} {
			if err := requireField(fields, required, path, item); err != nil {
				return nil, err
			}
		}

		name, err := stringValue(fields["name"], path+".name")
		if err != nil {
			return nil, err
		}
		socket, err := stringValue(fields["socket"], path+".socket")
		if err != nil {
			return nil, err
		}
		fingerprints, err := stringSequence(fields["fingerprints"], path+".fingerprints", locations)
		if err != nil {
			return nil, err
		}

		var accessGroup *uint32
		if groupNode, ok := fields["access-group"]; ok {
			group, err := integerValue(groupNode, path+".access-group")
			if err != nil {
				return nil, err
			}
			if group < 0 || group >= int64(^uint32(0)) {
				return nil, nodeError(path+".access-group", groupNode, "must be between 0 and 4294967294")
			}
			value := uint32(group)
			accessGroup = &value
		}
		consumers = append(consumers, Consumer{
			Name: name, Socket: socket, AccessGroup: accessGroup, Fingerprints: fingerprints,
		})
	}
	return consumers, nil
}

func decodeTimeouts(node *yaml.Node, locations map[string]*yaml.Node) (Timeouts, error) {
	fields, err := mapping(node, "timeouts", timeoutFields, locations)
	if err != nil {
		return Timeouts{}, err
	}
	for _, required := range []string{"connect", "list", "replay", "sign"} {
		if err := requireField(fields, required, "timeouts", node); err != nil {
			return Timeouts{}, err
		}
	}

	values := make(map[string]time.Duration, len(fields))
	for _, name := range []string{"connect", "list", "replay", "sign"} {
		path := "timeouts." + name
		text, err := stringValue(fields[name], path)
		if err != nil {
			return Timeouts{}, err
		}
		value, err := time.ParseDuration(text)
		if err != nil {
			return Timeouts{}, nodeError(path, fields[name], fmt.Sprintf("must be a Go duration: %v", err))
		}
		values[name] = value
	}
	return Timeouts{
		Connect: values["connect"], List: values["list"], Replay: values["replay"], Sign: values["sign"],
	}, nil
}

func mapping(node *yaml.Node, path string, allowed map[string]struct{}, locations map[string]*yaml.Node) (map[string]*yaml.Node, error) {
	if node.Kind != yaml.MappingNode {
		return nil, nodeError(path, node, "must be a mapping")
	}
	fields := make(map[string]*yaml.Node, len(node.Content)/2)
	for index := 0; index < len(node.Content); index += 2 {
		key := node.Content[index]
		value := node.Content[index+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return nil, nodeError(path, key, "field names must be strings")
		}
		fieldPath := joinPath(path, key.Value)
		if _, ok := allowed[key.Value]; !ok {
			return nil, nodeError(fieldPath, key, "unknown field")
		}
		if _, exists := fields[key.Value]; exists {
			return nil, nodeError(fieldPath, key, "field is defined more than once")
		}
		fields[key.Value] = value
		locations[fieldPath] = value
	}
	return fields, nil
}

func requireField(fields map[string]*yaml.Node, field, path string, parent *yaml.Node) error {
	if _, ok := fields[field]; ok {
		return nil
	}
	return nodeError(joinPath(path, field), parent, "field is required")
}

func stringValue(node *yaml.Node, path string) (string, error) {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return "", nodeError(path, node, "must be a string")
	}
	return node.Value, nil
}

func integerValue(node *yaml.Node, path string) (int64, error) {
	if node.Kind != yaml.ScalarNode || node.Tag != "!!int" {
		return 0, nodeError(path, node, "must be an integer")
	}
	var value int64
	if err := node.Decode(&value); err != nil {
		return 0, nodeError(path, node, fmt.Sprintf("must be an integer: %v", err))
	}
	return value, nil
}

func stringSequence(node *yaml.Node, path string, locations map[string]*yaml.Node) ([]string, error) {
	if node.Kind != yaml.SequenceNode {
		return nil, nodeError(path, node, "must be a sequence")
	}
	values := make([]string, 0, len(node.Content))
	for index, item := range node.Content {
		itemPath := fmt.Sprintf("%s[%d]", path, index)
		locations[itemPath] = item
		value, err := stringValue(item, itemPath)
		if err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, nil
}

func nodeError(field string, node *yaml.Node, problem string) error {
	return &FieldError{Field: field, Line: node.Line, Column: node.Column, Problem: problem}
}

func addLocation(err error, locations map[string]*yaml.Node) error {
	var fieldErr *FieldError
	if !errors.As(err, &fieldErr) || fieldErr.Line != 0 {
		return err
	}
	if node, ok := locations[fieldErr.Field]; ok {
		copy := *fieldErr
		copy.Line = node.Line
		copy.Column = node.Column
		return &copy
	}
	return err
}

func joinPath(prefix, field string) string {
	if prefix == "" {
		return field
	}
	return prefix + "." + field
}
