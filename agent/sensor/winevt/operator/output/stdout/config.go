// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stdout

import (
	"encoding/json"
	"io"
	"os"

	"ada/agent/sensor/winevt/operator"
	"ada/agent/sensor/winevt/operator/helper"
)

const operatorType = "stdout"

// Stdout is a global handle to standard output
var Stdout io.Writer = os.Stdout

func init() {
	operator.Register(operatorType, func() operator.Builder { return NewConfig("") })
}

// NewConfig creates a new stdout config with default values
func NewConfig(operatorID string) *Config {
	return &Config{
		OutputConfig: helper.NewOutputConfig(operatorID, operatorType),
	}
}

// Config is the configuration of the Stdout operator
type Config struct {
	helper.OutputConfig `mapstructure:",squash"`
}

// Build will build a stdout operator.
func (c Config) Build(set operator.BaseSettings) (operator.Operator, error) {
	outputOperator, err := c.OutputConfig.Build(set)
	if err != nil {
		return nil, err
	}

	return &Output{
		OutputOperator: outputOperator,
		encoder:        json.NewEncoder(Stdout),
	}, nil
}
