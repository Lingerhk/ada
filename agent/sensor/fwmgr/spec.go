package fwmgr

import "strings"

// Service names and event IDs of the two firewalls.
//
// RPC Firewall writes to the Application/RPCFW channel (message manifest
// rpcMessages: 1 PROCESS_PROTECTION_ADDED, 2 PROCESS_PROTECTION_REMOVED,
// 3 RPC_SERVER_CALL). LDAP Firewall writes to Application/LDAPFW
// (257 LDAP_PROTECTION_ADDED, 258 LDAP_PROTECTION_REMOVED per upstream docs).
const (
	RPCServiceName = "RPC Firewall"
	RPCChannel     = "RPCFW"
	rpcAddedID     = 1
	rpcRemovedID   = 2

	LDAPServiceName = "LDAP Firewall"
	LDAPChannel     = "LDAPFW"
	ldapAddedID     = 257
	ldapRemovedID   = 258
)

// RPCSpec returns the Spec for the RPC Firewall with the given manager
// executable and RpcFw.conf path.
func RPCSpec(exe, conf string) Spec {
	return Spec{
		Name: "rpcfw", Service: RPCServiceName, Exe: exe, Conf: conf,
		Channel: RPCChannel, AddedID: rpcAddedID, RemovedID: rpcRemovedID,
		Validate: ValidateRPCConf,
	}
}

// LDAPSpec returns the Spec for the LDAP Firewall with the given manager
// executable and config.json path.
func LDAPSpec(exe, conf string) Spec {
	return Spec{
		Name: "ldapfw", Service: LDAPServiceName, Exe: exe, Conf: conf,
		Channel: LDAPChannel, AddedID: ldapAddedID, RemovedID: ldapRemovedID,
		Validate: ValidateLDAPConf,
	}
}

func trim(s string) string { return strings.TrimSpace(s) }
