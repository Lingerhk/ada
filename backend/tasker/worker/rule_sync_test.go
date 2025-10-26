package worker

import "testing"

func TestRuleSyncTask(t *testing.T) {

	err := WCli.RuleSyncTask()
	if err != nil {
		t.Errorf("RuleSyncTask err:%v", err)
	}

	t.Log("RuleSyncTask ok!")
}
