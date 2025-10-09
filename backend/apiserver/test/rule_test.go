package test

import (
	v2 "ada/backend/apiserver/api/v2"
	"encoding/json"
	"testing"

	. "github.com/smartystreets/goconvey/convey"
)

// Test variables for rule IDs
var (
	testAlertRuleID    string
	testActivityRuleID string
)

// TestListAlertRule tests listing alert rules with various filters
func TestListAlertRule(t *testing.T) {
	Convey("Test ListAlertRule API", t, func() {
		req := &v2.ListAlertRuleReq{
			PageIdx:  1,
			PageSize: 10,
		}

		resp, err := ADACli.cli.ListAlertRule(ADACli.ctx, req)

		Convey("Should succeed without error", func() {
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.Page, ShouldNotBeNil)
		})

		Convey("Should return valid page info", func() {
			So(resp.Page.PageIdx, ShouldEqual, 1)
			So(resp.Page.Total, ShouldBeGreaterThanOrEqualTo, 0)
		})

		if len(resp.Rules) > 0 {
			t.Logf("Found %d alert rules", len(resp.Rules))
			for i, rule := range resp.Rules {
				t.Logf("Rule[%d]: ID=%s, Title=%s, Level=%d, Status=%s",
					i, rule.ID, rule.Title, rule.Level, rule.Status)
			}
		}
	})
}

// TestListAlertRuleWithFilters tests listing with various filter parameters
func TestListAlertRuleWithFilters(t *testing.T) {
	Convey("Test ListAlertRule with filters", t, func() {
		Convey("Filter by level", func() {
			req := &v2.ListAlertRuleReq{
				PageIdx:  1,
				PageSize: 10,
				Level:    []int32{4, 5}, // high and critical
			}

			resp, err := ADACli.cli.ListAlertRule(ADACli.ctx, req)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			for _, rule := range resp.Rules {
				So(rule.Level, ShouldBeIn, []int32{4, 5})
			}
		})

		Convey("Filter by keyword", func() {
			req := &v2.ListAlertRuleReq{
				PageIdx:  1,
				PageSize: 10,
				Keyword:  "password", // search in title/description
			}

			resp, err := ADACli.cli.ListAlertRule(ADACli.ctx, req)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			t.Logf("Found %d rules matching 'password'", len(resp.Rules))
		})

		Convey("Filter by status", func() {
			req := &v2.ListAlertRuleReq{
				PageIdx:  1,
				PageSize: 10,
				Status:   []string{"stable", "experimental"},
			}

			resp, err := ADACli.cli.ListAlertRule(ADACli.ctx, req)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			for _, rule := range resp.Rules {
				So(rule.Status, ShouldBeIn, []string{"stable", "experimental"})
			}
		})
	})
}

// TestAddAlertRule tests creating a new alert rule
func TestAddAlertRule(t *testing.T) {
	Convey("Test AddAlertRule API", t, func() {
		// Create detection JSON for flow rule
		detection := map[string]interface{}{
			"event_type":  "multi_eve",
			"win_size":    60,
			"sorted":      false,
			"sigma_rules": []string{"winlog-0000-0001", "winlog-0102-0001"},
			"match_by":    "$s1.TargetUserName == $s2.SubjectUserName",
		}
		detectionJSON, _ := json.Marshal(detection)

		req := &v2.AddAlertRuleReq{
			Title:       "Test Alert Rule - Automated Test",
			Description: "This is a test alert rule created by unit test",
			Enable:      true,
			Level:       3, // medium
			Status:      "test",
			Tags:        []string{"TA0001", "test"},
			Logsource:   "flow",
			Detection:   string(detectionJSON),
			Type:        "suspicious_activity",
			References:  []string{"https://attack.mitre.org/"},
			Suggestion:  "Review the activity and investigate if necessary",
			Author:      "unit_test",
			AutoBlock:   false,
		}

		resp, err := ADACli.cli.AddAlertRule(ADACli.ctx, req)

		Convey("Should succeed", func() {
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.Result, ShouldEqual, "SUCCESS")
			So(resp.ID, ShouldNotBeEmpty)
		})

		if resp != nil && resp.ID != "" {
			testAlertRuleID = resp.ID
			t.Logf("Created alert rule with ID: %s", testAlertRuleID)
		}
	})
}

// TestUpdateAlertRule tests updating an existing alert rule
func TestUpdateAlertRule(t *testing.T) {
	if testAlertRuleID == "" {
		t.Skip("Skipping update test - no alert rule ID available")
	}

	Convey("Test UpdateAlertRule API", t, func() {
		req := &v2.UpdateAlertRuleReq{
			ID:          testAlertRuleID,
			Title:       "Test Alert Rule - Updated",
			Description: "Updated description",
			Level:       4, // high
		}

		resp, err := ADACli.cli.UpdateAlertRule(ADACli.ctx, req)

		Convey("Should succeed", func() {
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.Result, ShouldEqual, "SUCCESS")
		})

		t.Logf("Updated alert rule: %s", testAlertRuleID)
	})
}

// TestDeleteAlertRule tests deleting an alert rule
func TestDeleteAlertRule(t *testing.T) {
	if testAlertRuleID == "" {
		t.Skip("Skipping delete test - no alert rule ID available")
	}

	Convey("Test DeleteAlertRule API", t, func() {
		req := &v2.DeleteAlertRuleReq{
			ID: testAlertRuleID,
		}

		resp, err := ADACli.cli.DeleteAlertRule(ADACli.ctx, req)

		Convey("Should succeed", func() {
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.Result, ShouldEqual, "SUCCESS")
		})

		t.Logf("Deleted alert rule: %s", testAlertRuleID)
	})
}

// TestListActivityRule tests listing Sigma rules
func TestListActivityRule(t *testing.T) {
	Convey("Test ListActivityRule API", t, func() {
		req := &v2.ListActivityRuleReq{
			PageIdx:  1,
			PageSize: 10,
		}

		resp, err := ADACli.cli.ListActivityRule(ADACli.ctx, req)

		Convey("Should succeed", func() {
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.Page, ShouldNotBeNil)
		})

		Convey("Should return valid page info", func() {
			So(resp.Page.PageIdx, ShouldEqual, 1)
			So(resp.Page.Total, ShouldBeGreaterThanOrEqualTo, 0)
		})

		if len(resp.Rules) > 0 {
			t.Logf("Found %d activity rules", len(resp.Rules))
			for i, rule := range resp.Rules {
				t.Logf("Rule[%d]: ID=%s, Title=%s, Level=%d, Logsource=%s",
					i, rule.ID, rule.Title, rule.Level, rule.Logsource)
			}
		}
	})
}

// TestListActivityRuleWithFilters tests listing with various filters
func TestListActivityRuleWithFilters(t *testing.T) {
	Convey("Test ListActivityRule with filters", t, func() {
		Convey("Filter by rule type (winlog)", func() {
			req := &v2.ListActivityRuleReq{
				PageIdx:  1,
				PageSize: 10,
				RuleType: "winlog",
			}

			resp, err := ADACli.cli.ListActivityRule(ADACli.ctx, req)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			for _, rule := range resp.Rules {
				So(rule.ID, ShouldStartWith, "winlog-")
			}
			t.Logf("Found %d winlog rules", len(resp.Rules))
		})

		Convey("Filter by rule type (pktlog)", func() {
			req := &v2.ListActivityRuleReq{
				PageIdx:  1,
				PageSize: 10,
				RuleType: "pktlog",
			}

			resp, err := ADACli.cli.ListActivityRule(ADACli.ctx, req)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			for _, rule := range resp.Rules {
				So(rule.ID, ShouldStartWith, "pktlog-")
			}
			t.Logf("Found %d pktlog rules", len(resp.Rules))
		})

		Convey("Filter by MITRE ATT&CK tags", func() {
			req := &v2.ListActivityRuleReq{
				PageIdx:  1,
				PageSize: 10,
				Tags:     []string{"TA0007"}, // Discovery tactic
			}

			resp, err := ADACli.cli.ListActivityRule(ADACli.ctx, req)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			t.Logf("Found %d rules with TA0007 tag", len(resp.Rules))
		})

		Convey("Filter by level (critical/high)", func() {
			req := &v2.ListActivityRuleReq{
				PageIdx:  1,
				PageSize: 10,
				Level:    []int32{4, 5},
			}

			resp, err := ADACli.cli.ListActivityRule(ADACli.ctx, req)
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)

			for _, rule := range resp.Rules {
				So(rule.Level, ShouldBeIn, []int32{4, 5})
			}
		})
	})
}

// TestGetActivityRule tests getting a specific activity rule by ID
func TestGetActivityRule(t *testing.T) {
	// First, list rules to get a valid ID
	listReq := &v2.ListActivityRuleReq{
		PageIdx:  1,
		PageSize: 1,
	}
	listResp, err := ADACli.cli.ListActivityRule(ADACli.ctx, listReq)
	if err != nil || len(listResp.Rules) == 0 {
		t.Skip("No activity rules available for testing GetActivityRule")
		return
	}

	ruleID := listResp.Rules[0].ID

	Convey("Test GetActivityRule API", t, func() {
		req := &v2.GetActivityRuleReq{
			ID: ruleID,
		}

		resp, err := ADACli.cli.GetActivityRule(ADACli.ctx, req)

		Convey("Should succeed", func() {
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.ID, ShouldEqual, ruleID)
			So(resp.Detection, ShouldNotBeEmpty) // Should have detection JSON
		})

		if resp != nil {
			t.Logf("Activity Rule Details:")
			t.Logf("  ID: %s", resp.ID)
			t.Logf("  Title: %s", resp.Title)
			t.Logf("  Level: %d", resp.Level)
			t.Logf("  Status: %s", resp.Status)
			t.Logf("  Tags: %v", resp.Tags)
			t.Logf("  Detection: %s", resp.Detection[:min(100, len(resp.Detection))])
		}
	})
}

// TestAddActivityRule tests creating a new Sigma rule
func TestAddActivityRule(t *testing.T) {
	Convey("Test AddActivityRule API", t, func() {
		// Create detection JSON for winlog rule
		detection := map[string]interface{}{
			"selection1": map[string]interface{}{
				"EventID":          4625,
				"LogonType":        3,
				"LogonProcessName": "NtLmSsp",
			},
			"condition": "selection1",
		}
		detectionJSON, _ := json.Marshal(detection)

		req := &v2.AddActivityRuleReq{
			ID:          "winlog-9999-9999", // Test rule ID
			Title:       "Test Failed Logon - Automated Test",
			Description: "Detects failed logon attempts for testing",
			Level:       2, // low
			Status:      "test",
			Tags:        []string{"TA0001", "T1078", "test"},
			Logsource:   "windows",
			References:  []string{"https://attack.mitre.org/techniques/T1078/"},
			Detection:   string(detectionJSON),
			RdxKey:      "rule_cache:test_failed_logon",
			Fields:      []string{"Hostname", "TargetUserName", "IpAddress"},
			UniqueFields: []string{"Hostname", "TargetUserName"},
			Author:      "unit_test",
		}

		resp, err := ADACli.cli.AddActivityRule(ADACli.ctx, req)

		Convey("Should succeed", func() {
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.Result, ShouldEqual, "SUCCESS")
			So(resp.ID, ShouldEqual, "winlog-9999-9999")
		})

		if resp != nil && resp.ID != "" {
			testActivityRuleID = resp.ID
			t.Logf("Created activity rule with ID: %s", testActivityRuleID)
		}
	})
}

// TestUpdateActivityRule tests updating an existing Sigma rule
func TestUpdateActivityRule(t *testing.T) {
	if testActivityRuleID == "" {
		t.Skip("Skipping update test - no activity rule ID available")
	}

	Convey("Test UpdateActivityRule API", t, func() {
		req := &v2.UpdateActivityRuleReq{
			ID:          testActivityRuleID,
			Title:       "Test Failed Logon - Updated",
			Description: "Updated description for test rule",
			Level:       3, // medium
		}

		resp, err := ADACli.cli.UpdateActivityRule(ADACli.ctx, req)

		Convey("Should succeed", func() {
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.Result, ShouldEqual, "SUCCESS")
		})

		t.Logf("Updated activity rule: %s", testActivityRuleID)
	})
}

// TestDeleteActivityRule tests deleting a Sigma rule
func TestDeleteActivityRule(t *testing.T) {
	if testActivityRuleID == "" {
		t.Skip("Skipping delete test - no activity rule ID available")
	}

	Convey("Test DeleteActivityRule API", t, func() {
		req := &v2.DeleteActivityRuleReq{
			ID: testActivityRuleID,
		}

		resp, err := ADACli.cli.DeleteActivityRule(ADACli.ctx, req)

		Convey("Should succeed", func() {
			So(err, ShouldBeNil)
			So(resp, ShouldNotBeNil)
			So(resp.Result, ShouldEqual, "SUCCESS")
		})

		t.Logf("Deleted activity rule: %s", testActivityRuleID)
	})
}

// TestActivityRuleWithComplexDetection tests rules with complex detection structures
func TestActivityRuleWithComplexDetection(t *testing.T) {
	Convey("Test ActivityRule with complex detection", t, func() {
		// Flow rule with multiple sigma rules
		detection := map[string]interface{}{
			"event_type": "count",
			"win_size":   "30s",
			"selection": map[string]interface{}{
				"sigma_id": []string{"winlog-0101-0002"},
				"match_by": "$s1._count >= 5",
			},
		}
		detectionJSON, _ := json.Marshal(detection)

		req := &v2.AddActivityRuleReq{
			ID:          "flow-9999-0001",
			Title:       "Test Brute Force Detection",
			Description: "Detects multiple failed logon attempts",
			Level:       4,
			Status:      "test",
			Tags:        []string{"TA0006", "T1110"},
			Logsource:   "flow",
			Detection:   string(detectionJSON),
			Author:      "unit_test",
		}

		resp, err := ADACli.cli.AddActivityRule(ADACli.ctx, req)
		So(err, ShouldBeNil)
		So(resp, ShouldNotBeNil)

		if resp != nil && resp.ID != "" {
			t.Logf("Created complex rule: %s", resp.ID)

			// Clean up
			deleteReq := &v2.DeleteActivityRuleReq{ID: resp.ID}
			ADACli.cli.DeleteActivityRule(ADACli.ctx, deleteReq)
		}
	})
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
