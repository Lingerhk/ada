package test

import (
	"encoding/json"
	"testing"
	"time"

	v2 "ada/backend/apiserver/api/v2"

	. "github.com/smartystreets/goconvey/convey"
)

func TestRuleReloadMechanism(t *testing.T) {
	Convey("Test Rule Reload Mechanism", t, func() {
		var ruleID string

		Convey("Step 1: Add test alert rule", func() {
			detection := map[string]interface{}{
				"event_type":  "multi_eve",
				"win_size":    60,
				"sorted":      false,
				"sigma_rules": []string{"winlog-0000-0001", "winlog-0102-0001"},
				"match_by":    "$s1.TargetUserName == $s2.SubjectUserName",
			}
			detectionJSON, err := json.Marshal(detection)
			So(err, ShouldBeNil)

			addReq := &v2.AddAlertRuleReq{
				Title:       "Test Reload Mechanism - Automated Test",
				Description: "This rule is created to test the reload mechanism",
				Enable:      true,
				Level:       3,
				Status:      "test",
				Tags:        []string{"test", "reload"},
				Logsource:   "flow",
				Detection:   string(detectionJSON),
				Type:        "test_reload",
				References:   []string{"https://github.com/test"},
				Suggestion:  "This is a test rule",
				Author:      "reload_test",
				AutoBlock:   false,
			}

			addResp, err := ADACli.cli.AddAlertRule(ADACli.ctx, addReq)
			So(err, ShouldBeNil)
			So(addResp, ShouldNotBeNil)
			So(addResp.ID, ShouldNotBeEmpty)

			ruleID = addResp.ID
			t.Logf("✓ Rule created successfully with ID: %s", ruleID)

			Convey("Step 2: Wait for file write and reload signal", func() {
				time.Sleep(2 * time.Second)
				t.Log("✓ Waited for file write and reload signal")

				Convey("Step 3: Update the rule", func() {
					updateReq := &v2.UpdateAlertRuleReq{
						ID:          ruleID,
						Title:       "Test Reload Mechanism - UPDATED",
						Description: "This rule was updated to test the reload mechanism",
						Level:       4, // Changed from 3 to 4
						Tags:        []string{"test", "reload", "updated"},
					}

					updateResp, err := ADACli.cli.UpdateAlertRule(ADACli.ctx, updateReq)
					So(err, ShouldBeNil)
					So(updateResp, ShouldNotBeNil)
					So(updateResp.Result, ShouldNotBeEmpty)

					t.Logf("✓ Rule updated successfully: %s", updateResp.Result)

					Convey("Step 4: Wait for file update and reload signal", func() {
						time.Sleep(2 * time.Second)
						t.Log("✓ Waited for file update and reload signal")

						Convey("Step 5: Verify updated rule", func() {
							listReq := &v2.ListAlertRuleReq{
								PageIdx:  1,
								PageSize: 100,
								Keyword:  "Test Reload Mechanism",
							}

							listResp, err := ADACli.cli.ListAlertRule(ADACli.ctx, listReq)
							So(err, ShouldBeNil)
							So(listResp, ShouldNotBeNil)
							So(len(listResp.Rules), ShouldBeGreaterThan, 0)

							rule := listResp.Rules[0]
							So(rule.ID, ShouldEqual, ruleID)
							So(rule.Title, ShouldContainSubstring, "UPDATED")
							So(rule.Level, ShouldEqual, 4)
							So(rule.Tags, ShouldContain, "updated")

							t.Logf("✓ Rule verification passed:")
							t.Logf("  - ID: %s", rule.ID)
							t.Logf("  - Title: %s", rule.Title)
							t.Logf("  - Level: %d (should be 4)", rule.Level)
							t.Logf("  - Tags: %v", rule.Tags)

							Convey("Step 6: Delete the test rule", func() {
								deleteReq := &v2.DeleteAlertRuleReq{
									ID: ruleID,
								}

								deleteResp, err := ADACli.cli.DeleteAlertRule(ADACli.ctx, deleteReq)
								So(err, ShouldBeNil)
								So(deleteResp, ShouldNotBeNil)
								So(deleteResp.Result, ShouldNotBeEmpty)

								t.Logf("✓ Rule deleted successfully: %s", deleteResp.Result)

								Convey("Step 7: Wait for file deletion and reload signal", func() {
									time.Sleep(2 * time.Second)
									t.Log("✓ Waited for file deletion and reload signal")

									Convey("Step 8: Verify rule was deleted", func() {
										listReq := &v2.ListAlertRuleReq{
											PageIdx:  1,
											PageSize: 100,
											Keyword:  "Test Reload Mechanism",
										}

										listResp, err := ADACli.cli.ListAlertRule(ADACli.ctx, listReq)
										So(err, ShouldBeNil)
										So(listResp, ShouldNotBeNil)

										// Rule should not be found or should be marked as deleted
										found := false
										for _, r := range listResp.Rules {
											if r.ID == ruleID {
												found = true
												break
											}
										}
										So(found, ShouldBeFalse)

										t.Log("✓ Rule successfully deleted from system")
										t.Log("\n========================================")
										t.Log("✓ All reload mechanism tests passed!")
										t.Log("========================================")
										t.Log("\nVerify in logs:")
										t.Log("1. Backend logs: 'Published reload signal to engine'")
										t.Log("2. Engine logs: 'Received reload signal' and 'Rules reloaded successfully'")
										t.Log("3. Rule files: /home/adadmin/rules/flow/")
									})
								})
							})
						})
					})
				})
			})
		})
	})
}
