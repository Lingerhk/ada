package fwctl

// protectionActiveFromEvents decides whether protection is currently applied,
// given the firewall's protect-added / protect-removed events in newest-first
// order. Both firewalls log an "added" event when protection is installed and
// a "removed" event when it is torn down, so the most recent of the two tells
// us the live state. With no such event, protection is treated as inactive.
func protectionActiveFromEvents(newestFirstIDs []int, addedID, removedID int) bool {
	for _, id := range newestFirstIDs {
		switch id {
		case addedID:
			return true
		case removedID:
			return false
		}
	}
	return false
}

// Event IDs, from the firewalls' message manifests / upstream documentation.
const (
	rpcProtectionAddedID   = 1 // Application/RPCFW: PROCESS_PROTECTION_ADDED
	rpcProtectionRemovedID = 2 // Application/RPCFW: PROCESS_PROTECTION_REMOVED
	rpcEventChannel        = "RPCFW"

	ldapProtectionAddedID   = 257 // Application/LDAPFW: LDAP_PROTECTION_ADDED
	ldapProtectionRemovedID = 258 // Application/LDAPFW: LDAP_PROTECTION_REMOVED
	ldapEventChannel        = "LDAPFW"
)
