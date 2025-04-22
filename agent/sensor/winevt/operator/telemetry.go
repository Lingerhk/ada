// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package operator

import "github.com/sirupsen/logrus"

// TelemetrySettings contains components for telemetry.
type TelemetrySettings struct {
	Logger *logrus.Logger
}
