package worker

import (
	"context"
	"testing"
)

func TestADLdapSync(t *testing.T) {

	err := WCli.ADLdapSyncTask(context.Background())
	if err != nil {
		t.Errorf("ADLdapSyncTask err:%v", err)
	}

	t.Log("ADLdapSyncTask ok!")
}
