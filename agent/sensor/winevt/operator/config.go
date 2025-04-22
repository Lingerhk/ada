// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package operator

import (
	"encoding/json"
	"fmt"
)

// Config is the configuration of an operator
type Config struct {
	Builder
}

// NewConfig wraps the builder interface in a concrete struct
func NewConfig(b Builder) Config {
	return Config{Builder: b}
}

// Builder is an entity that can build a single operator
type Builder interface {
	ID() string
	Type() string
	Build(TelemetrySettings) (Operator, error)
	SetID(string)
}

// UnmarshalJSON will unmarshal a config from JSON.
func (c *Config) UnmarshalJSON(bytes []byte) error {
	var typeUnmarshaller struct {
		Type string
	}

	if err := json.Unmarshal(bytes, &typeUnmarshaller); err != nil {
		return err
	}

	if typeUnmarshaller.Type == "" {
		return fmt.Errorf("missing required field 'type'")
	}

	builderFunc, ok := DefaultRegistry.Lookup(typeUnmarshaller.Type)
	if !ok {
		return fmt.Errorf("unsupported type '%s'", typeUnmarshaller.Type)
	}

	builder := builderFunc()
	if err := json.Unmarshal(bytes, builder); err != nil {
		return fmt.Errorf("unmarshal to %s: %w", typeUnmarshaller.Type, err)
	}

	c.Builder = builder
	return nil
}

// UnmarshalYAML will unmarshal a config from YAML.
func (c *Config) UnmarshalYAML(unmarshal func(any) error) error {
	rawConfig := map[string]any{}
	err := unmarshal(&rawConfig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal yaml to base config: %w", err)
	}

	typeInterface, ok := rawConfig["type"]
	if !ok {
		return fmt.Errorf("missing required field 'type'")
	}

	typeString, ok := typeInterface.(string)
	if !ok {
		return fmt.Errorf("non-string type %T for field 'type'", typeInterface)
	}

	builderFunc, ok := DefaultRegistry.Lookup(typeString)
	if !ok {
		return fmt.Errorf("unsupported type '%s'", typeString)
	}

	builder := builderFunc()
	if err = unmarshal(builder); err != nil {
		return fmt.Errorf("unmarshal to %s: %w", typeString, err)
	}

	c.Builder = builder
	return nil
}
