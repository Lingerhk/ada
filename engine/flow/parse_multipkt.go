package flow

import (
	"context"
)

func (r *Ruleset) matchEventMultiPkt(ctx context.Context, fr FlowRule, flowInstances []string) {
	r.matchEventSequence(ctx, fr, flowInstances, "multi-pkt")
}
