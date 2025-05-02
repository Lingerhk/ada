// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package syslog

import (
	"ada/agent/sensor/winevt/operator/output/syslog/wsyslog"
	"encoding/json"

	"ada/agent/sensor/winevt/operator"
	"ada/agent/sensor/winevt/operator/helper"
)

const operatorType = "syslog"

func init() {
	operator.Register(operatorType, func() operator.Builder { return NewConfig("") })
}

// NewConfig creates a new syslog config with default values
func NewConfig(operatorID string) *Config {
	return &Config{
		OutputConfig: helper.NewOutputConfig(operatorID, operatorType),
	}
}

// Config is the configuration of the Syslog operator
type Config struct {
	helper.OutputConfig `mapstructure:",squash"`
	Network             string           `mapstructure:"network"` // "tcp", "udp", etc.
	Address             string           `mapstructure:"address"` // "localhost:514"
	Priority            wsyslog.Priority `mapstructure:"priority"`
	Tag                 string           `mapstructure:"tag"`
	Hostname            string           `mapstructure:"hostname"`
}

// Build will build a syslog operator.
func (c Config) Build(set operator.BaseSettings) (operator.Operator, error) {
	outputOperator, err := c.OutputConfig.Build(set)
	if err != nil {
		return nil, err
	}

	// Use syslog writer instead of stdout
	priority := wsyslog.Priority(wsyslog.LOG_INFO)
	writer, err := wsyslog.Dial(c.Network, c.Address, priority, c.Tag)
	if err != nil {
		return nil, err
	}
	writer.SetHostname(c.Hostname)
	writer.SetFormatter(wsyslog.RFC3164Formatter)

	return &Output{
		OutputOperator: outputOperator,
		encoder:        json.NewEncoder(writer),
	}, nil
}
