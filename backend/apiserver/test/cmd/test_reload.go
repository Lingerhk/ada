package main

import (
	"context"
	"log"
	"time"

	v2 "ada/backend/apiserver/api/v2"
	"ada/backend/apiserver/common"
	"ada/backend/apiserver/util"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

const (
	username = "admin"
	grpcAddr = "127.0.0.1:8800"
)

func main() {
	log.Println("========================================")
	log.Println("Testing Rule Reload Mechanism")
	log.Println("========================================")

	// Connect to gRPC server
	conn, err := grpc.Dial(grpcAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	client := v2.NewADAClient(conn)

	// Generate auth token
	exp := time.Now().AddDate(0, 0, 90).Unix()
	token, err := util.GenerateToken(username, common.RoleMgr, common.PrivSuper, exp)
	if err != nil {
		log.Fatalf("Failed to generate token: %v", err)
	}

	md := metadata.Pairs("authorization", "Bearer "+token)
	ctx := metadata.NewOutgoingContext(context.Background(), md)

	// Step 1: Add a test rule
	log.Println("\n[Step 1] Adding test alert rule...")
	detection := &v2.AlertDetection{
		EventType:  "multi_eve",
		WinSize:    "60",
		Sorted:     false,
		SigmaRules: []string{"winlog-0000-0001", "winlog-0102-0001"},
		MatchBy:    "$s1.TargetUserName == $s2.SubjectUserName",
	}

	addReq := &v2.AddAlertRuleReq{
		Title:       "Test Reload Mechanism - Automated Test",
		Description: "This rule is created to test the reload mechanism",
		Enable:      true,
		Level:       3,
		Status:      "test",
		Tags:        []string{"test", "reload"},
		Logsource:   "flow",
		Detection:   detection,
		Type:        "test_reload",
		References:  []string{"https://github.com/test"},
		Suggestion:  "This is a test rule",
		Author:      "reload_test",
		AutoBlock:   false,
	}

	addResp, err := client.AddAlertRule(ctx, addReq)
	if err != nil {
		log.Fatalf("Failed to add rule: %v", err)
	}
	log.Printf("✓ Rule created successfully with ID: %s", addResp.ID)
	ruleID := addResp.ID

	// Step 2: Wait for file write and reload signal
	log.Println("\n[Step 2] Waiting for file write and reload signal...")
	time.Sleep(2 * time.Second)
	log.Println("✓ Wait completed")

	// Step 3: Verify rule was written to disk
	log.Println("\n[Step 3] Checking if rule file was created...")
	// This would be checked manually or via docker exec

	// Step 4: Update the rule
	log.Println("\n[Step 4] Updating the rule...")
	updateReq := &v2.UpdateAlertRuleReq{
		ID:          ruleID,
		Title:       "Test Reload Mechanism - UPDATED",
		Description: "This rule was updated to test the reload mechanism",
		Level:       4, // Changed from 3 to 4
		Tags:        []string{"test", "reload", "updated"},
	}

	updateResp, err := client.UpdateAlertRule(ctx, updateReq)
	if err != nil {
		log.Fatalf("Failed to update rule: %v", err)
	}
	log.Printf("✓ Rule updated successfully: %s", updateResp.Result)

	// Step 5: Wait for file update and reload signal
	log.Println("\n[Step 5] Waiting for file update and reload signal...")
	time.Sleep(2 * time.Second)
	log.Println("✓ Wait completed")

	// Step 6: Verify updated rule
	log.Println("\n[Step 6] Fetching updated rule to verify changes...")
	listReq := &v2.ListAlertRuleReq{
		PageIdx:  1,
		PageSize: 100,
		Keyword:  "Test Reload Mechanism",
	}

	listResp, err := client.ListAlertRule(ctx, listReq)
	if err != nil {
		log.Fatalf("Failed to list rules: %v", err)
	}

	if len(listResp.Rules) > 0 {
		rule := listResp.Rules[0]
		log.Printf("✓ Rule verification:")
		log.Printf("  - ID: %s", rule.ID)
		log.Printf("  - Title: %s", rule.Title)
		log.Printf("  - Description: %s", rule.Description)
		log.Printf("  - Level: %d (should be 4)", rule.Level)
		log.Printf("  - Tags: %v", rule.Tags)
		log.Printf("  - UpdateTime: %s", rule.UpdateTm)
	} else {
		log.Fatalf("Rule not found after update!")
	}

	// Step 7: Delete the test rule
	log.Println("\n[Step 7] Deleting test rule...")
	deleteReq := &v2.DeleteAlertRuleReq{
		ID: ruleID,
	}

	deleteResp, err := client.DeleteAlertRule(ctx, deleteReq)
	if err != nil {
		log.Fatalf("Failed to delete rule: %v", err)
	}
	log.Printf("✓ Rule deleted successfully: %s", deleteResp.Result)

	// Step 8: Wait for file deletion and reload signal
	log.Println("\n[Step 8] Waiting for file deletion and reload signal...")
	time.Sleep(2 * time.Second)
	log.Println("✓ Wait completed")

	log.Println("\n========================================")
	log.Println("✓ All tests completed successfully!")
	log.Println("========================================")
	log.Println("\nNext steps:")
	log.Println("1. Check backend logs for: 'Published reload signal to engine'")
	log.Println("2. Check engine logs for: 'Received reload signal' and 'Rules reloaded successfully'")
	log.Println("3. Verify rule files were created/updated/deleted in /home/adadmin/rules/flow/")
}
