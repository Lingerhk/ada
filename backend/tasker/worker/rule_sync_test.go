package worker

import (
	"context"
	"testing"
)

func TestRuleSyncTask(t *testing.T) {

	err := WCli.RuleSyncTask(context.Background())
	if err != nil {
		t.Errorf("RuleSyncTask err:%v", err)
	}

	t.Log("RuleSyncTask ok!")
}
