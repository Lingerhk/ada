package server

import (
	"testing"
)

func TestUpdateScanConfByDomain(t *testing.T) {
	domain := "chinasix.com"

	// add scan conf for this domain in tb_scan_conf.plans
	err := UpdateScanConfByDomain(env, domain, false)
	if err != nil {
		t.Error(err.Error())
	}
}
