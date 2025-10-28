package main

import (
	"ada/backend/apiserver/config"
	"ada/backend/apiserver/server"
	"ada/backend/model"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Sigma rule YAML structure
type SigmaRule struct {
	Title        string                 `yaml:"title"`
	ID           string                 `yaml:"id"`
	Status       string                 `yaml:"status"`
	Description  string                 `yaml:"description"`
	References   []string               `yaml:"references"`
	Author       string                 `yaml:"author"`
	Date         string                 `yaml:"date"`
	Modified     string                 `yaml:"modified"`
	Tags         []string               `yaml:"tags"`
	Logsource    map[string]interface{} `yaml:"logsource"`
	Detection    map[string]interface{} `yaml:"detection"`
	Fields       []string               `yaml:"fields"`
	UniqueFields []string               `yaml:"unique_fields"`
	RdxKey       string                 `yaml:"rdx_key"`
	Level        string                 `yaml:"level"`
}

func levelToInt(level string) int32 {
	switch strings.ToLower(level) {
	case "info", "informational":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	default:
		return 3 // default to medium
	}
}

func getLogsource(logsourceMap map[string]interface{}) string {
	if logsourceMap == nil {
		return ""
	}

	if product, ok := logsourceMap["product"].(string); ok {
		if product == "sigma_flow" {
			return "flow"
		}
		return product
	}
	return ""
}

func importFlowRules(env *config.Env, rulesDir string) error {
	files, err := ioutil.ReadDir(rulesDir)
	if err != nil {
		return fmt.Errorf("failed to read flow rules directory: %v", err)
	}

	count := 0
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".yml") && !strings.HasSuffix(file.Name(), ".yaml") {
			continue
		}

		filePath := filepath.Join(rulesDir, file.Name())
		data, err := ioutil.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Error reading %s: %v\n", file.Name(), err)
			continue
		}

		var rule SigmaRule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			fmt.Printf("Error parsing %s: %v\n", file.Name(), err)
			continue
		}

		winSize, ok := rule.Detection["win_size"]
		if !ok {
			fmt.Print("invalid win_size in detection")
			continue
		}

		// Create AlertRule for flow rules
		alertRule := &model.AlertRule{
			ID:          rule.ID,
			Title:       rule.Title,
			Description: rule.Description,
			Enable:      true,
			Level:       levelToInt(rule.Level),
			Status:      rule.Status,
			Tags:        rule.Tags,
			Logsource:   "flow",
			Detection: model.AlertDetection{
				EventType:  getEventType(rule.Detection),
				WinSize:    winSize.(string),
				SigmaRules: getSigmaIDs(rule.Detection),
				MatchBy:    getMatchBy(rule.Detection),
			},
			Type:       "correlation",
			References: rule.References,
			Author:     rule.Author,
			AutoBlock:  false,
			CreateTm:   time.Now(),
			UpdateTm:   time.Now(),
		}

		if err := server.AddAlertRule(env, alertRule); err != nil {
			fmt.Printf("Failed to import flow rule %s: %v\n", rule.ID, err)
		} else {
			count++
			fmt.Printf("✓ Imported flow rule: %s - %s\n", rule.ID, rule.Title)
		}
	}

	fmt.Printf("\nImported %d flow rules\n", count)
	return nil
}

func importActivityRules(env *config.Env, rulesDir string, ruleType string) error {
	files, err := os.ReadDir(rulesDir)
	if err != nil {
		return fmt.Errorf("failed to read %s rules directory: %v", ruleType, err)
	}

	count := 0
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".yml") && !strings.HasSuffix(file.Name(), ".yaml") {
			continue
		}

		filePath := filepath.Join(rulesDir, file.Name())
		data, err := os.ReadFile(filePath)
		if err != nil {
			fmt.Printf("Error reading %s: %v\n", file.Name(), err)
			continue
		}

		var rule SigmaRule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			fmt.Printf("Error parsing %s: %v\n", file.Name(), err)
			continue
		}

		// Create AlertActivityRule for winlog/pktlog rules
		activityRule := &model.AlertActivityRule{
			ID:           rule.ID,
			Title:        rule.Title,
			Description:  rule.Description,
			Level:        levelToInt(rule.Level),
			Status:       rule.Status,
			Tags:         rule.Tags,
			Logsource:    getLogsource(rule.Logsource),
			References:   rule.References,
			Detection:    rule.Detection,
			RdxKey:       rule.RdxKey,
			Fields:       rule.Fields,
			UniqueFields: rule.UniqueFields,
			Author:       rule.Author,
			CreateTm:     time.Now(),
			UpdateTm:     time.Now(),
		}

		if err := server.AddActivityRule(env, activityRule); err != nil {
			fmt.Printf("Failed to import %s rule %s: %v\n", ruleType, rule.ID, err)
		} else {
			count++
			fmt.Printf("✓ Imported %s rule: %s - %s\n", ruleType, rule.ID, rule.Title)
		}
	}

	fmt.Printf("\nImported %d %s rules\n", count, ruleType)
	return nil
}

// Helper functions to extract detection fields for flow rules
func getEventType(detection map[string]any) string {
	if et, ok := detection["event_type"].(string); ok {
		return et
	}
	return ""
}

func getSigmaIDs(detection map[string]any) []string {
	var sigmaIDs []string

	// Check selection.sigma_id
	if selection, ok := detection["selection"].(map[string]any); ok {
		if ids, ok := selection["sigma_id"].([]any); ok {
			for _, id := range ids {
				if idStr, ok := id.(string); ok {
					sigmaIDs = append(sigmaIDs, idStr)
				}
			}
		}
	}

	return sigmaIDs
}

func getMatchBy(detection map[string]any) string {
	// Check selection.match_by
	if selection, ok := detection["selection"].(map[string]any); ok {
		if matchBy, ok := selection["match_by"].(string); ok {
			return matchBy
		}
	}

	// Check top-level match_by
	if matchBy, ok := detection["match_by"].(string); ok {
		return matchBy
	}

	return ""
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run import_rules.go <config_path>")
		fmt.Println("Example: go run import_rules.go /tmp/apiserver.yaml")
		os.Exit(1)
	}

	configPath := os.Args[1]

	// Load configuration
	env, err := config.Init(configPath)
	if err != nil {
		fmt.Printf("Failed to initialize config: %v\n", err)
		os.Exit(1)
	}

	rulesBaseDir := "/home/adadmin/adaegis/ada/engine/rules"

	fmt.Println("=== Importing Flow Rules to tb_alert_rule ===")
	if err := importFlowRules(env, filepath.Join(rulesBaseDir, "flow")); err != nil {
		fmt.Printf("Error importing flow rules: %v\n", err)
	}

	fmt.Println("\n=== Importing Winlog Rules to tb_activity_rule ===")
	if err := importActivityRules(env, filepath.Join(rulesBaseDir, "winlog"), "winlog"); err != nil {
		fmt.Printf("Error importing winlog rules: %v\n", err)
	}

	fmt.Println("\n=== Importing Pktlog Rules to tb_activity_rule ===")
	if err := importActivityRules(env, filepath.Join(rulesBaseDir, "pktlog"), "pktlog"); err != nil {
		fmt.Printf("Error importing pktlog rules: %v\n", err)
	}

	fmt.Println("\n✅ Import completed!")
}
