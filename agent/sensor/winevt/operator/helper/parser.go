// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"context"
	"fmt"

	"ada/agent/sensor/winevt/entry"
	"ada/agent/sensor/winevt/errors"
	"ada/agent/sensor/winevt/operator"
)

// NewParserConfig creates a new parser config with default values
func NewParserConfig(operatorID, operatorType string) ParserConfig {
	return ParserConfig{
		TransformerConfig: NewTransformerConfig(operatorID, operatorType),
		ParseFrom:         entry.NewBodyField(),
		ParseTo:           entry.RootableField{Field: entry.NewAttributeField()},
	}
}

// ParserConfig provides the basic implementation of a parser config.
type ParserConfig struct {
	TransformerConfig `mapstructure:",squash"`
	ParseFrom         entry.Field         `mapstructure:"parse_from"`
	ParseTo           entry.RootableField `mapstructure:"parse_to"`
	BodyField         *entry.Field        `mapstructure:"body"`
}

// Build will build a parser operator.
func (c ParserConfig) Build(set operator.TelemetrySettings) (ParserOperator, error) {
	transformerOperator, err := c.TransformerConfig.Build(set)
	if err != nil {
		return ParserOperator{}, err
	}

	if c.BodyField != nil && c.ParseTo.String() == entry.NewBodyField().String() {
		return ParserOperator{}, fmt.Errorf("`parse_to: body` not allowed when `body` is configured")
	}

	parserOperator := ParserOperator{
		TransformerOperator: transformerOperator,
		ParseFrom:           c.ParseFrom,
		ParseTo:             c.ParseTo.Field,
		BodyField:           c.BodyField,
	}

	return parserOperator, nil
}

// ParserOperator provides a basic implementation of a parser operator.
type ParserOperator struct {
	TransformerOperator
	ParseFrom entry.Field
	ParseTo   entry.Field
	BodyField *entry.Field
}

// ProcessWith will run ParseWith on the entry, then forward the entry on to the next operators.
func (p *ParserOperator) ProcessWith(ctx context.Context, entry *entry.Entry, parse ParseFunction) error {
	return p.ProcessWithCallback(ctx, entry, parse, nil)
}

func (p *ParserOperator) ProcessWithCallback(ctx context.Context, entry *entry.Entry, parse ParseFunction, cb func(*entry.Entry) error) error {
	// Short circuit if the "if" condition does not match
	skip, err := p.Skip(ctx, entry)
	if err != nil {
		return p.HandleEntryError(ctx, entry, err)
	}
	if skip {
		return p.Write(ctx, entry)
	}

	if err = p.ParseWith(ctx, entry, parse); err != nil {
		if p.OnError == DropOnErrorQuiet || p.OnError == SendOnErrorQuiet {
			return nil
		}

		return err
	}
	if cb != nil {
		err = cb(entry)
		if err != nil {
			return p.HandleEntryError(ctx, entry, err)
		}
	}

	return p.Write(ctx, entry)
}

// ParseWith will process an entry's field with a parser function.
func (p *ParserOperator) ParseWith(ctx context.Context, entry *entry.Entry, parse ParseFunction) error {
	value, ok := entry.Get(p.ParseFrom)
	if !ok {
		err := errors.NewError(
			"Entry is missing the expected parse_from field.",
			"Ensure that all incoming entries contain the parse_from field.",
			"parse_from", p.ParseFrom.String(),
		)
		return p.HandleEntryError(ctx, entry, err)
	}

	newValue, err := parse(value)
	if err != nil {
		return p.HandleEntryError(ctx, entry, err)
	}

	if err := entry.Set(p.ParseTo, newValue); err != nil {
		return p.HandleEntryError(ctx, entry, errors.Wrap(err, "set parse_to"))
	}

	if p.BodyField != nil {
		if body, ok := p.BodyField.Get(entry); ok {
			entry.Body = body
		}
	}

	return nil
}

// ParseFunction is function that parses a raw value.
type ParseFunction = func(any) (any, error)
