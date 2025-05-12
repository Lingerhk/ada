// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package operator

import "github.com/sirupsen/logrus"

// BaseSettings contains components for telemetry.
type BaseSettings struct {
	Logger *logrus.Logger
}
