package flow

import (
	"context"
)

func (r *Ruleset) matchEventMultiEvePkt(ctx context.Context, fr FlowRule, flowInstances []string) {
	r.matchEventSequence(ctx, fr, flowInstances, "multi-eve-pkt")
}
