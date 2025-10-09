package model

// This file provides examples of how to work with ActivityDetection

// Example 1: Parsing winlog/pktlog rule detection
func ExampleWinlogDetection() ActivityDetection {
	return ActivityDetection{
		"selection1": map[string]any{
			"EventID":          4624,
			"LogonType":        3,
			"LogonProcessName": "Kerberos",
		},
		"filter1": map[string]any{
			"IpAddress": []string{"::1", "fe80", "127.0.0.1"},
		},
		"filter2": map[string]any{
			"TargetUserSid|contains": []string{"S-1-5-18", "S-1-5-90-0-"},
		},
		"filter3": map[string]any{
			"TargetUserName|endswith": "$",
		},
		"condition": "selection1 and not filter1 and not filter2 and not filter3",
	}
}

// Example 2: Parsing flow rule detection (count type)
func ExampleFlowCountDetection() ActivityDetection {
	return ActivityDetection{
		"event_type": "count",
		"win_size":   "30s",
		"selection": map[string]any{
			"sigma_id": []string{"winlog-0101-0002"},
			"match_by": "$s1._count == 3",
		},
	}
}

// Example 3: Parsing flow rule detection (multi_eve type)
func ExampleFlowMultiEveDetection() ActivityDetection {
	return ActivityDetection{
		"event_type": "multi_eve",
		"win_size":   "60s",
		"sorted":     false,
		"selection": map[string]any{
			"sigma_id": []string{"winlog-0000-0001", "winlog-0102-0001"},
			"match_by": "$s1.TargetUserName == $s2.SubjectUserName AND $s1.Hostname == $s2.Hostname",
		},
	}
}

// Helper function to determine if detection is a flow rule
func (d ActivityDetection) IsFlowRule() bool {
	_, hasEventType := d["event_type"]
	return hasEventType
}

// Helper function to get condition from winlog/pktlog detection
func (d ActivityDetection) GetCondition() string {
	if cond, ok := d["condition"].(string); ok {
		return cond
	}
	return ""
}

// Helper function to get event_type from flow detection
func (d ActivityDetection) GetEventType() string {
	if et, ok := d["event_type"].(string); ok {
		return et
	}
	return ""
}

// Helper function to get win_size from flow detection
func (d ActivityDetection) GetWinSize() string {
	if ws, ok := d["win_size"].(string); ok {
		return ws
	}
	return ""
}
