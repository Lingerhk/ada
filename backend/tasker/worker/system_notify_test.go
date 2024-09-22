package worker

import "testing"

func TestSystemNotifyTask(t *testing.T) {

	err := WCli.SystemNotifyTask()
	if err != nil {
		t.Errorf("SystemNotifyTask err:%v", err)
	}

	t.Log("SystemNotifyTask ok!")
}
