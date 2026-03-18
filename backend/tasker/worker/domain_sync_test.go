package worker

import (
	"context"
	"testing"
)

func TestDomainSyncTask(t *testing.T) {

	err := WCli.DomainSyncTask(context.Background())
	if err != nil {
		t.Errorf("DomainSyncTask err:%v", err)
	}

	t.Log("DomainSyncTask ok!")
}
