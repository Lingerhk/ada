package worker

import (
	"context"
	"testing"
)

func TestSystemNotifyTask(t *testing.T) {

	err := WCli.SystemNotifyTask(context.Background())
	if err != nil {
		t.Errorf("SystemNotifyTask err:%v", err)
	}

	t.Log("SystemNotifyTask ok!")
}
