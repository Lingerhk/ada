// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"ada/agent/sensor/winevt/errors"
	"ada/agent/sensor/winevt/operator"

	"github.com/sirupsen/logrus"
)

// NewBasicConfig creates a new basic config
func NewBasicConfig(operatorID, operatorType string) BasicConfig {
	return BasicConfig{
		OperatorID:   operatorID,
		OperatorType: operatorType,
	}
}

// BasicConfig provides a basic implemention for an operator config.
type BasicConfig struct {
	OperatorID   string `mapstructure:"id"`
	OperatorType string `mapstructure:"type"`
}

// ID will return the operator id.
func (c BasicConfig) ID() string {
	if c.OperatorID == "" {
		return c.OperatorType
	}
	return c.OperatorID
}

// SetID will Update the operator id.
func (c *BasicConfig) SetID(id string) {
	c.OperatorID = id
}

// Type will return the operator type.
func (c BasicConfig) Type() string {
	return c.OperatorType
}

// Build will build a basic operator.
func (c BasicConfig) Build(set operator.BaseSettings) (BasicOperator, error) {
	if c.OperatorType == "" {
		return BasicOperator{}, errors.NewError(
			"missing required `type` field.",
			"ensure that all operators have a uniquely defined `type` field.",
			"operator_id", c.ID(),
		)
	}

	if set.Logger == nil {
		return BasicOperator{}, errors.NewError(
			"operator build context is missing a logger.",
			"this is an unexpected internal error",
			"operator_id", c.ID(),
			"operator_type", c.Type(),
		)
	}

	//set.Logger = set.Logger.With(logrus.String("operator_id", c.ID()), logrus.String("operator_type", c.Type()))
	operator := BasicOperator{
		OperatorID:   c.ID(),
		OperatorType: c.Type(),
		set:          set,
	}

	return operator, nil
}

// BasicOperator provides a basic implementation of an operator.
type BasicOperator struct {
	OperatorID   string
	OperatorType string
	set          operator.BaseSettings
}

// ID will return the operator id.
func (p *BasicOperator) ID() string {
	if p.OperatorID == "" {
		return p.OperatorType
	}
	return p.OperatorID
}

// Type will return the operator type.
func (p *BasicOperator) Type() string {
	return p.OperatorType
}

// Logger returns the operator's scoped logger.
func (p *BasicOperator) Logger() *logrus.Logger {
	return p.set.Logger
}

// Start will start the operator.
func (p *BasicOperator) Start(_ operator.Persister) error {
	return nil
}

// Stop will stop the operator.
func (p *BasicOperator) Stop() error {
	return nil
}
