package flow

import (
	"context"
	logger "github.com/sirupsen/logrus"
)

func (r *Ruleset) matchEventMultiEvePkt(ctx context.Context, fr FlowRule, flowInstances []string) {
	logger.Warnf("we do not support the %s type event flow, will ignore!", fr.Detection.EventType)
}
