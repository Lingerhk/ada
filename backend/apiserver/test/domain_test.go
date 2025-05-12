package test

import (
	v2 "ada/backend/apiserver/api/v2"
	"ada/infra/ldap"
	"testing"

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
		t.Error(err.Error())
	}

	for _, domain := range resp.List {
		t.Logf("%#v", domain)
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
		t.Error(err.Error())
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
		t.Error(err.Error())
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
		Password: "adaegis123OK123",
		DNS:      "192.168.18.221",
	}
	resp, err := ADACli.cli.TestDomain(ADACli.ctx, &req)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("%#v", resp)
}

func TestLdapConn(t *testing.T) {
	ldapAddr := "ldap://DC2019-01.chinanin.com"
	username := "administrator@chinanin.com"
	password := "adaegis123OK123"
	dns := "192.168.18.221"

	resp, err := ldap.GetConn(ldapAddr, username, password, dns)
	if err != nil {
		t.Error(err.Error())
	}

	t.Logf("ldap conn ok:%#v", resp)
}
