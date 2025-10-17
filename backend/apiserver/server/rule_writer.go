package server

import (
	"ada/backend/apiserver/config"
	"ada/backend/cache"
	"ada/backend/common"
	"ada/backend/model"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	logger "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// AlertRuleYAML represents the YAML structure for flow/alert rules
type AlertRuleYAML struct {
	ID          string                 `yaml:"id"`
	Title       string                 `yaml:"title"`
	Description string                 `yaml:"description,omitempty"`
	Level       string                 `yaml:"level"`
	Status      string                 `yaml:"status"`
	Tags        []string               `yaml:"tags,omitempty"`
	Logsource   string                 `yaml:"logsource,omitempty"`
	Detection   map[string]interface{} `yaml:"detection"`
	Type        string                 `yaml:"type,omitempty"`
	References  []string               `yaml:"references,omitempty"`
	Suggestion  string                 `yaml:"suggestion,omitempty"`
	Author      string                 `yaml:"author,omitempty"`
	AutoBlock   bool                   `yaml:"auto_block,omitempty"`
}

// ActivityRuleYAML represents the YAML structure for sigma/activity rules
type ActivityRuleYAML struct {
	ID          string                 `yaml:"id"`
	Title       string                 `yaml:"title"`
	Description string                 `yaml:"description,omitempty"`
	Level       string                 `yaml:"level"`
	Status      string                 `yaml:"status"`
	Tags        []string               `yaml:"tags,omitempty"`
	Logsource   string                 `yaml:"logsource,omitempty"`
	Detection   map[string]interface{} `yaml:"detection"`
	References  []string               `yaml:"references,omitempty"`
	Author      string                 `yaml:"author,omitempty"`
	RdxKey      string                 `yaml:"rdx_key,omitempty"`
	Fields      []string               `yaml:"fields,omitempty"`
}

// WriteAlertRuleToFile writes an AlertRule to a YAML file
func WriteAlertRuleToFile(rule *model.AlertRule) error {
	// Ensure directory exists
	ruleDir := filepath.Join(common.ROOT_PATH, "rules", common.RuleTypeFlow)
	if err := os.MkdirAll(ruleDir, 0755); err != nil {
		return fmt.Errorf("failed to create rule directory: %v", err)
	}

	// Convert to YAML structure
	yamlRule := AlertRuleYAML{
		ID:          rule.ID,
		Title:       rule.Title,
		Description: rule.Description,
		Level:       LevelIntToString(rule.Level),
		Status:      rule.Status,
		Tags:        rule.Tags,
		Logsource:   rule.Logsource,
		Detection: map[string]interface{}{
			"event_type": rule.Detection.EventType,
			"match_by":   rule.Detection.MatchBy,
			"win_size":   rule.Detection.WinSize,
			"sorted":     rule.Detection.Sorted,
		},
		Type:       rule.Type,
		References: rule.References,
		Suggestion: rule.Suggestion,
		Author:     rule.Author,
		AutoBlock:  rule.AutoBlock,
	}

	if len(rule.Detection.SigmaRules) > 0 {
		yamlRule.Detection["sigma_rules"] = rule.Detection.SigmaRules
	}

	// Marshal to YAML
	data, err := yaml.Marshal(yamlRule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule to YAML: %v", err)
	}

	// Write to file
	filename := filepath.Join(ruleDir, fmt.Sprintf("%s.yaml", rule.ID))
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write rule file: %v", err)
	}

	logger.Infof("Wrote alert rule to %s", filename)
	return nil
}

// WriteActivityRuleToFile writes an ActivityRule to a YAML file
func WriteActivityRuleToFile(rule *model.AlertActivityRule) error {
	// Determine rule type from ID prefix (winlog-*, pktlog-*, flow-*)
	var ruleDir string
	if len(rule.ID) >= 6 && rule.ID[:6] == "winlog" {
		ruleDir = filepath.Join(common.ROOT_PATH, "rules", common.RuleTypeWinLog)
	} else if len(rule.ID) >= 6 && rule.ID[:6] == "pktlog" {
		ruleDir = filepath.Join(common.ROOT_PATH, "rules", common.RuleTypePktLog)
	} else {
		return fmt.Errorf("invalid activity rule ID format: %s (must start with winlog- or pktlog-)", rule.ID)
	}

	// Ensure directory exists
	if err := os.MkdirAll(ruleDir, 0755); err != nil {
		return fmt.Errorf("failed to create rule directory: %v", err)
	}

	// Convert to YAML structure
	yamlRule := ActivityRuleYAML{
		ID:          rule.ID,
		Title:       rule.Title,
		Description: rule.Description,
		Level:       LevelIntToString(rule.Level),
		Status:      rule.Status,
		Tags:        rule.Tags,
		Logsource:   rule.Logsource,
		Detection:   rule.Detection,
		References:  rule.References,
		Author:      rule.Author,
		RdxKey:      rule.RdxKey,
		Fields:      rule.Fields,
	}

	// Marshal to YAML
	data, err := yaml.Marshal(yamlRule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule to YAML: %v", err)
	}

	// Write to file
	filename := filepath.Join(ruleDir, fmt.Sprintf("%s.yaml", rule.ID))
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write rule file: %v", err)
	}

	logger.Infof("Wrote activity rule to %s", filename)
	return nil
}

// DeleteAlertRuleFile deletes an AlertRule YAML file
func DeleteAlertRuleFile(ruleID string) error {
	ruleDir := filepath.Join(common.ROOT_PATH, "rules", common.RuleTypeFlow)
	filename := filepath.Join(ruleDir, fmt.Sprintf("%s.yaml", ruleID))

	if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete rule file: %v", err)
	}

	logger.Infof("Deleted alert rule file %s", filename)
	return nil
}

// DeleteActivityRuleFile deletes an ActivityRule YAML file
func DeleteActivityRuleFile(ruleID string) error {
	// Determine rule type from ID prefix
	var ruleDir string
	if len(ruleID) >= 6 && ruleID[:6] == "winlog" {
		ruleDir = filepath.Join(common.ROOT_PATH, "rules", common.RuleTypeWinLog)
	} else if len(ruleID) >= 6 && ruleID[:6] == "pktlog" {
		ruleDir = filepath.Join(common.ROOT_PATH, "rules", common.RuleTypePktLog)
	} else {
		return fmt.Errorf("invalid activity rule ID format: %s", ruleID)
	}

	filename := filepath.Join(ruleDir, fmt.Sprintf("%s.yaml", ruleID))

	if err := os.Remove(filename); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete rule file: %v", err)
	}

	logger.Infof("Deleted activity rule file %s", filename)
	return nil
}

// SendReloadSignalToEngine sends a reload signal to the engine via Redis pub/sub
// This works across Docker containers since both backend and engine share the same Redis instance
func SendReloadSignalToEngine(env *config.Env) error {
	ctx := context.Background()

	// Publish reload message to Redis channel
	message := fmt.Sprintf("reload:%d", time.Now().Unix())
	err := env.RedisCli.Publish(ctx, cache.EngineReloadChannel, message).Err()
	if err != nil {
		logger.Errorf("Failed to publish reload signal to engine: %v", err)
		return err
	}

	logger.Infof("Published reload signal to engine via Redis channel '%s'", cache.EngineReloadChannel)
	return nil
}

// SyncAllRulesToDisk synchronizes all rules from database to disk files
func SyncAllRulesToDisk(e *config.Env) error {
	logger.Info("Syncing all rules from database to disk...")

	// Sync alert rules
	alertRules, _, err := ListAlertRule(e, []int32{}, []string{}, nil, "", []string{}, -1, 10000, 0)
	if err != nil {
		return fmt.Errorf("failed to list alert rules: %v", err)
	}

	for _, rule := range alertRules {
		if err := WriteAlertRuleToFile(rule); err != nil {
			logger.Errorf("Failed to write alert rule %s: %v", rule.ID, err)
		}
	}

	// Sync activity rules
	activityRules, _, err := ListActivityRule(e, []string{}, []int32{}, []string{}, "", []string{}, "", "", -1, 10000, 0)
	if err != nil {
		return fmt.Errorf("failed to list activity rules: %v", err)
	}

	for _, rule := range activityRules {
		if err := WriteActivityRuleToFile(rule); err != nil {
			logger.Errorf("Failed to write activity rule %s: %v", rule.ID, err)
		}
	}

	logger.Infof("Synced %d alert rules and %d activity rules to disk", len(alertRules), len(activityRules))

	// Generate version.txt file after all rules are written
	if err := GenerateVersionFile(); err != nil {
		logger.Errorf("Failed to generate version file: %v", err)
	} else {
		logger.Info("Generated version.txt file")
	}

	return nil
}

// GenerateVersionFile creates a version.txt file with current timestamp and build time
func GenerateVersionFile() error {
	// Create rules directory if it doesn't exist
	rulesDir := filepath.Join(common.ROOT_PATH, "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		return fmt.Errorf("failed to create rules directory: %v", err)
	}

	// Get current time
	now := time.Now()
	timestamp := now.Unix()
	buildTime := now.Format("2006-01-02 15:04:05")

	// Create version file content
	versionContent := fmt.Sprintf("version: %d\nbuild_time: %s\n", timestamp, buildTime)

	// Write version.txt file
	versionFilePath := filepath.Join(rulesDir, "version.txt")
	if err := os.WriteFile(versionFilePath, []byte(versionContent), 0644); err != nil {
		return fmt.Errorf("failed to write version file: %v", err)
	}

	logger.Infof("Generated version.txt with timestamp: %d, build_time: %s", timestamp, buildTime)
	return nil
}
