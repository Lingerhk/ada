// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package syslog

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"ada/agent/sensor/winevt/entry"
	"ada/agent/sensor/winevt/operator/helper"
)

// Output is an operator that logs entries using stdout.
type Output struct {
	helper.OutputOperator
	encoder *json.Encoder
	mux     sync.Mutex
}

func (o *Output) ProcessBatch(ctx context.Context, entries []*entry.Entry) error {
	var errs []error
	for i := range entries {
		errs = append(errs, o.Process(ctx, entries[i]))
	}
	return errors.Join(errs...)
}

// Process will log entries received.
func (o *Output) Process(_ context.Context, entry *entry.Entry) error {
	o.mux.Lock()
	err := o.encoder.Encode(entry)
	if err != nil {
		o.mux.Unlock()
		o.Logger().Errorf("Failed to process entry, error: %v", err)
		return err
	}
	o.mux.Unlock()
	return nil
}
