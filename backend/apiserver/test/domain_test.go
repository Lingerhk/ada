package test

import (
	v2 "ada/backend/apiserver/api/v2"
	"ada/infra/ldap"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/masterzen/winrm"
	. "github.com/smartystreets/goconvey/convey"
)

func TestListDomainList(t *testing.T) {
	req := v2.ListDomainReq{
		FilterDomain:  "",
		FilterStatus:  "",
		FilterKeyword: "",
		PageSize:      10,
		PageIdx:       1,
	}
	resp, err := ADACli.cli.ListDomain(ADACli.ctx, &req)
	if err != nil {
		t.Fatal(err.Error())
	}

	for _, domain := range resp.List {
		t.Logf("%#v", domain)
		for idx, dc := range domain.DCs {
			t.Logf("dc[%d]: %#v", idx, dc)
		}
	}
}

func TestAddDomain(t *testing.T) {
	req := v2.AddDomainReq{
		LdapAddr: "ldap://DC2016-01.chinasix.com",
		Username: "CHINASIX\\Administrator",
		Password: "ada@2024abc",
		DNS:      "192.168.18.216",
	}

	resp, err := ADACli.cli.AddDomain(ADACli.ctx, &req)
	if err != nil {
		t.Fatal(err.Error())
	}
	Convey("Test API AddDomain", t, func() {
		Convey("Test response status", func() {
			So(resp.Result, ShouldEqual, "success")
		})
	})
}

func TestUpdateDomain(t *testing.T) {
	req := v2.UpdateDomainReq{
		ID:       "6623982d96f73185bd193df4",
		LdapAddr: "ldap://DC2016-01.chinasix.com",
		Username: "CHINASIX\\Administrator",
		Password: "ada@2024abc123",
		DNS:      "192.168.18.216",
	}

	resp, err := ADACli.cli.UpdateDomain(ADACli.ctx, &req)
	if err != nil {
		t.Fatal(err.Error())
	}
	Convey("Test API UpdateDomain", t, func() {
		Convey("Test response status", func() {
			So(resp.Result, ShouldEqual, "success")
		})
	})
}

func TestTestDomain(t *testing.T) {
	req := v2.TestDomainReq{
		LdapAddr: "DC2019-01.chinanin.com",
		Username: "administrator@chinanin.com",
		Password: "dc2019@pass",
		DNS:      "192.168.18.221",
	}
	resp, err := ADACli.cli.TestDomain(ADACli.ctx, &req)
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestLdapConn(t *testing.T) {
	ldapAddr := "ldap://DC2019-01.chinanin.com"
	username := "administrator@chinanin.com"
	password := "dc2019@pass"
	dns := "192.168.18.221"

	resp, err := ldap.GetConn(ldapAddr, username, password, dns)
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Logf("ldap conn ok:%#v", resp)
}

func TestDeploySensor(t *testing.T) {
	req := v2.DeploySensorReq{
		DomainID:   "65a8cc5d02a0e274892b87ed",
		DcHostname: "DC2019-01",
	}

	resp, err := ADACli.cli.DeploySensor(ADACli.ctx, &req)
	if err != nil {
		t.Fatal(err.Error())
	}

	t.Logf("deploy sensor resp:%#v", resp)
}

func TestWinRmCmd(t *testing.T) {
	portal := "192.168.6.4"
	targetIP := "192.168.6.219"
	username := "CHINA.COM\\administrator"
	//username := "administrator@china.com"
	password := "dc2019@pass"

	winrmConfig := winrm.NewEndpoint(
		targetIP,      // Host
		5985,          // Port (HTTP)
		false,         // TLS
		false,         // InsecureSkipVerify
		nil,           // CACert
		nil,           // Cert
		nil,           // Key
		3*time.Second, // Timeout in seconds
	)

	winrmClient, err := winrm.NewClient(winrmConfig, username, password)
	if err != nil {
		panic(err)
	}

	downloadCmd := fmt.Sprintf(`Invoke-WebRequest -Uri "http://%s/download/sensor/install-adaegis.ps1" -OutFile "C:\install-adaegis.ps1"`, portal)
	execCtx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	downloadStdout, downloadStderr, downloadCode, err := winrmClient.RunPSWithContext(execCtx, downloadCmd)
	if err != nil || downloadCode != 0 {
		t.Errorf("winrm execute err:%v, code:%d, stdout:%s, stderr:%s", err, downloadCode, downloadStdout, downloadStderr)
		return
	}

	t.Logf("winrm execute stdout:%s, stderr:%s, code:%d", downloadStdout, downloadStderr, downloadCode)
}
