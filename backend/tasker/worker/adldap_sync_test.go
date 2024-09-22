package worker

import (
	"testing"
)

func TestADLdapSync(t *testing.T) {

	err := WCli.ADLdapSyncTask()
	if err != nil {
		t.Errorf("ADLdapSyncTask err:%v", err)
	}

	t.Log("ADLdapSyncTask ok!")
}
