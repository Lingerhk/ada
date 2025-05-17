package worker

import "testing"

func TestDomainSyncTask(t *testing.T) {

	err := WCli.DomainSyncTask()
	if err != nil {
		t.Errorf("DomainSyncTask err:%v", err)
	}

	t.Log("DomainSyncTask ok!")
}
