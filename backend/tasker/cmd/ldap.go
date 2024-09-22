package main

import (
	"ada/infra/base"
	"ada/infra/ldap"
	"ada/infra/ldap/uac"
	"encoding/base64"
	"fmt"
	"strings"
)

func main() {
	DN := "DC=china,DC=com"
	//filter := "(&(objectCategory=person)(objectClass=user))"
	filter := "(&(objectCategory=user)(sAMAccountName=Marcellus.Perkins))"
	//attributes := []string{"sAMAccountName", "userAccountControl"}

	attrs := "name,sAMAccountName,dn,objectSid,whenCreated,whenChanged,lastLogon,pwdLastSet,email,primaryGroupID,objectGUID,userAccountControl"
	attributes := strings.Split(attrs, ",")
	var pageSize uint32 = 100

	server := "ldap://192.168.6.219:389"
	dns := ""
	user := "administrator@china.com"
	password := "Iams0nnet"

	result, err := ldap.SearchWithPage(server, dns, DN, user, password, filter, attributes, pageSize)
	if err != nil {
		fmt.Printf("init ldap connect err:%v", err)
		panic(err)
	}
	if len(result.Entries) <= 0 {
		fmt.Println("empty  result")
		return
	}

	for _, entry := range result.Entries {
		//sAMAccountName := entry.GetAttributeValues("sAMAccountName")
		//fmt.Println(sAMAccountName)
		for _, attr := range entry.Attributes {
			switch attr.Name {
			case "cn":
				cn := attr.Values[0]
				fmt.Printf("cn:%s\n", cn)
			case "description":
				description := attr.Values[0]
				fmt.Printf("description:%s\n", description)
			case "sAMAccountName":
				sAMAccountName := attr.Values[0]
				fmt.Printf("sAMAccountName:%s\n", sAMAccountName)
			case "objectSid":
				b64sid := base64.StdEncoding.EncodeToString([]byte(attr.Values[0]))
				bsid, _ := base64.StdEncoding.DecodeString(b64sid)
				sid := ldap.SIDDecode(bsid)
				fmt.Printf("sid:%s\n", sid.String())
			case "userAccountControl":
				flags, err := uac.ParseUAC(base.Atoll(attr.Values[0]))
				if err != nil {
					panic(err)
				}
				fmt.Printf("flags:%#v\n", flags)
			}
		}

	}
}
