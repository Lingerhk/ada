//go:build windows

package fwctl

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// queryProtectionActive reads the last few protect/unprotect events from the
// firewall's event channel and decides whether protection is live. It uses
// wevtutil with a fixed, non-interpolated argument vector (no shell), bounded
// by ctx.
func queryProtectionActive(ctx context.Context, channel string, addedID, removedID int) (bool, error) {
	query := fmt.Sprintf("*[System[(EventID=%d or EventID=%d)]]", addedID, removedID)
	cmd := exec.CommandContext(ctx, "wevtutil.exe", "qe", channel,
		"/q:"+query, "/c:10", "/rd:true", "/f:xml")
	out, err := cmd.Output()
	if err != nil {
		return false, fmt.Errorf("query %s events: %w", channel, err)
	}
	return protectionActiveFromEvents(parseEventIDs(string(out)), addedID, removedID), nil
}

// parseEventIDs pulls the EventID values, in document order, out of the XML
// rendered by "wevtutil qe ... /f:xml". wevtutil with /rd:true renders newest
// first, which is the order protectionActiveFromEvents expects.
func parseEventIDs(xml string) []int {
	var ids []int
	for {
		i := strings.Index(xml, "<EventID")
		if i < 0 {
			break
		}
		xml = xml[i:]
		gt := strings.IndexByte(xml, '>')
		end := strings.Index(xml, "</EventID>")
		if gt < 0 || end < 0 || gt > end {
			break
		}
		if v, err := strconv.Atoi(strings.TrimSpace(xml[gt+1 : end])); err == nil {
			ids = append(ids, v)
		}
		xml = xml[end+len("</EventID>"):]
	}
	return ids
}
