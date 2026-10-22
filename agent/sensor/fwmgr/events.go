package fwmgr

// protectionApplied decides, from a firewall's protect-added / protect-removed
// event IDs in most-recent-first order, whether protection is currently
// applied. The most recent of the two events wins; other event IDs (e.g. the
// per-call audit events) are skipped. No relevant event means not applied.
func protectionApplied(newestFirst []int, addedID, removedID int) bool {
	for _, id := range newestFirst {
		switch id {
		case addedID:
			return true
		case removedID:
			return false
		}
	}
	return false
}
