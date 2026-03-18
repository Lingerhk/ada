package worker

import (
	"ada/backend/cache"
	"ada/backend/common"
	"ada/backend/model"
	"ada/infra/license"
	netutil "ada/infra/net"
	"ada/infra/version"
	"archive/zip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
	"gopkg.in/yaml.v3"
)

// RuleVersionInfo represents the version information from latest.json
type RuleVersionInfo struct {
	Version string `json:"version"`
	MD5     string `json:"md5"`
}

// RuleMetadata represents a single rule metadata in desc.json
type RuleMetadata struct {
	ID           string `json:"id"`
	UpdateTm     int64  `json:"update_tm"`
	Filename     string `json:"filename"`
	MD5          string `json:"md5"`
	DetectionMD5 string `json:"detection_md5"`
}

// RuleDescriptor represents the desc.json structure
type RuleDescriptor struct {
	Version string         `json:"version"`
	Flow    []RuleMetadata `json:"flow"`
	PktLog  []RuleMetadata `json:"pktlog"`
	WinLog  []RuleMetadata `json:"winlog"`
}

// RuleSyncTask executes rule synchronization from remote server
func (w *Worker) RuleSyncTask(ctx context.Context) error {
	w = w.withContext(ctx)
	time.Sleep(10 * time.Second) // wait 10s for case: first run at the process started(wait for other service ready)

	rulesPath := filepath.Join(common.ROOT_PATH, "download", "rules")

	// Get system info to check UpgradeRule setting
	var sysInfo model.SystemInfo
	_, exist := w.env.MongoCli.FindOne(sysInfo.CollectName(), bson.M{}, &sysInfo)
	if !exist {
		logger.Warn("System info not found, skipping rule sync")
		return nil
	}

	if sysInfo.UpgradeSrv == "" {
		logger.Warn("UpgradeSrv not configured, skipping rule sync")
		return nil
	}

	// Ensure rules directory exists
	if err := os.MkdirAll(rulesPath, 0755); err != nil {
		logger.Errorf("Failed to create rules directory: %v", err)
		return err
	}

	latestJSONPath := filepath.Join(rulesPath, "latest.json")
	latestZIPPath := filepath.Join(rulesPath, "latest.zip")
	currentVersionPath := filepath.Join(rulesPath, "current_version.txt")

	var descPath string
	var extractDir string

	if !sysInfo.UpgradeRule {
		// Mode 1: Check if both files exist locally and perform upgrade
		if _, err := os.Stat(latestJSONPath); os.IsNotExist(err) {
			logger.Info("UpgradeRule is false and latest.json not found, skipping")
			return nil
		}
		if _, err := os.Stat(latestZIPPath); os.IsNotExist(err) {
			logger.Info("UpgradeRule is false and latest.zip not found, skipping")
			return nil
		}

		logger.Info("Executing rule upgrade from local files")
		var err error
		descPath, extractDir, err = w.executeRuleUpgradeWithPaths(ctx, latestJSONPath, latestZIPPath, rulesPath)
		if err != nil {
			return err
		}
	} else {
		// Mode 2: Download from remote and check version
		logger.Infof("Checking latest rule version from remote %s", sysInfo.UpgradeSrv)

		// Get proxy settings
		upgradeProxy := false
		httpProxy := ""
		if sysInfo.SystemProxy != nil {
			upgradeProxy = sysInfo.SystemProxy["upgrade_proxy"] == "true"
			httpProxy = sysInfo.SystemProxy["http_proxy"]
		}

		latestVersion, err := w.checkLatestVersion(ctx, sysInfo.UpgradeSrv, latestJSONPath, currentVersionPath, upgradeProxy, httpProxy)
		if err != nil {
			return err
		}
		if latestVersion == "" {
			logger.Info("No update rule verion, skipping..")
			return nil
		}

		// Download latest.zip
		logger.Infof("New version %s available, downloading rule package", latestVersion)
		if err := w.downloadLatestZIP(ctx, sysInfo.UpgradeSrv, latestZIPPath, upgradeProxy, httpProxy); err != nil {
			logger.Errorf("Failed to download latest.zip: %v", err)
			return err
		}

		// Execute rule upgrade
		descPath, extractDir, err = w.executeRuleUpgradeWithPaths(ctx, latestJSONPath, latestZIPPath, rulesPath)
		if err != nil {
			return err
		}
	}

	// Step 4: Rule upload - upload local-only or updated rules (after sync completed)
	logger.Info("Step 4: Checking for local-only or updated rules to upload")

	// Get proxy settings for upload
	upgradeProxy := false
	httpProxy := ""
	if sysInfo.SystemProxy != nil {
		upgradeProxy = sysInfo.SystemProxy["upgrade_proxy"] == "true"
		httpProxy = sysInfo.SystemProxy["http_proxy"]
	}

	if err := w.uploadLocalRules(ctx, descPath, extractDir, sysInfo.UpgradeSrv, rulesPath, upgradeProxy, httpProxy); err != nil {
		logger.Errorf("Failed to upload local rules: %v", err)
		// Don't return error, just log it - upload is optional
	}

	return nil
}

// checkLatestVersion downloads the latest.json from remote server and check if need update
func (w *Worker) checkLatestVersion(ctx context.Context, upgradeSrv, destPath, currentVersionPath string, upgradeProxy bool, httpProxy string) (string, error) {
	// Ensure proper URL joining, handle trailing slash
	requestURL := fmt.Sprintf("%s/rule/version/latest.json", strings.TrimSuffix(upgradeSrv, "/"))

	// Create HTTP client with proxy support
	var client *http.Client
	if upgradeProxy && httpProxy != "" {
		client = netutil.NewHTTPClientWithProxy(httpProxy, 10)
	} else {
		client = netutil.NewHTTPClient(10)
	}

	req, err := http.NewRequestWithContext(ctx, "GET", requestURL, nil)
	if err != nil {
		logger.Errorf("new http request(%s) err:%v", requestURL, err)
		return "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		logger.Errorf("check rule version request(%s) err:%v", requestURL, err)
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", httpStatusError("check rule version", requestURL, resp)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse version info
	var remoteVersion RuleVersionInfo
	if err := json.Unmarshal(body, &remoteVersion); err != nil {
		return "", fmt.Errorf("failed to parse version info: %w", err)
	}

	// compare version
	data, err := os.ReadFile(currentVersionPath)
	if err != nil {
		if os.IsNotExist(err) {
			// No local version, need upgrade
			// save the latest.json to local
			if err := os.WriteFile(destPath, body, 0644); err != nil {
				return "", fmt.Errorf("failed to write latest.json: %w", err)
			}

			logger.Infof("local version file not exist, will update to latest version:%s", remoteVersion.Version)
			return remoteVersion.Version, nil
		}
		return "", fmt.Errorf("failed to read local version: %w", err)
	}

	currentVersion := strings.TrimSpace(string(data))

	// Compare versions (simple string comparison, assumes YYYYMMDDXX format)
	if remoteVersion.Version > currentVersion {
		logger.Infof("version upgrade detected: %s -> %s", currentVersion, remoteVersion.Version)

		// save the latest.json to local
		if err := os.WriteFile(destPath, body, 0644); err != nil {
			return "", fmt.Errorf("failed to write latest.json: %w", err)
		}
		return remoteVersion.Version, nil
	}

	return "", nil
}

// downloadLatestZIP downloads the latest.zip from remote server
func (w *Worker) downloadLatestZIP(ctx context.Context, upgradeSrv, destPath string, upgradeProxy bool, httpProxy string) error {
	// Ensure proper URL joining, handle trailing slash
	baseURL := strings.TrimSuffix(upgradeSrv, "/")

	// Build URL with query parameters
	u, err := url.Parse(fmt.Sprintf("%s/rule/package/latest.zip", baseURL))
	if err != nil {
		return fmt.Errorf("failed to parse URL: %w", err)
	}

	// Add version and trait parameters
	q := u.Query()
	q.Set("v", version.GetBuildVersion())
	q.Set("trait", license.GetTrait())
	u.RawQuery = q.Encode()

	logger.Infof("Downloading from: %s", u.String())

	// Create HTTP client with proxy support
	var client *http.Client
	if upgradeProxy && httpProxy != "" {
		client = netutil.NewHTTPClientWithProxy(httpProxy, 60)
	} else {
		client = netutil.NewHTTPClient(60)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create download request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to download latest.zip: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return httpStatusError("download latest.zip", u.String(), resp)
	}

	// Create output file
	out, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create latest.zip: %w", err)
	}
	defer out.Close()

	// Copy response body to file
	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("failed to write latest.zip: %w", err)
	}

	return nil
}

// executeRuleUpgradeWithPaths performs the rule upgrade operation and returns paths
func (w *Worker) executeRuleUpgradeWithPaths(ctx context.Context, jsonPath, zipPath, rulesPath string) (string, string, error) {
	// Step 1: Check MD5
	var versionInfo RuleVersionInfo
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to read version file: %w", err)
	}
	if err := json.Unmarshal(data, &versionInfo); err != nil {
		return "", "", fmt.Errorf("failed to parse version info: %w", err)
	}

	// Calculate ZIP file MD5
	zipMD5, err := calculateFileMD5(zipPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to calculate ZIP MD5: %w", err)
	}

	if zipMD5 != versionInfo.MD5 {
		return "", "", fmt.Errorf("MD5 mismatch: expected %s, got %s", versionInfo.MD5, zipMD5)
	}
	logger.Info("MD5 verification passed!")

	// Step 2: Extract and validate structure
	extractDir, err := w.extractAndValidateZIP(zipPath, rulesPath)
	if err != nil {
		return "", "", fmt.Errorf("failed to extract ZIP: %w", err)
	}
	logger.Infof("Extracted rule package to: %s", extractDir)

	// Step 3: Parse desc.json and update database
	descPath := filepath.Join(extractDir, "desc.json")
	if err := w.updateRulesFromDescriptor(ctx, descPath, extractDir); err != nil {
		return "", "", fmt.Errorf("failed to update rules: %w", err)
	}

	logger.Info("Rule upgrade completed successfully!")

	// Step 4: Save current version to current_version.txt
	versionFilePath := filepath.Join(rulesPath, "current_version.txt")
	if err := os.WriteFile(versionFilePath, []byte(versionInfo.Version), 0644); err != nil {
		logger.Errorf("Failed to save current version to file: %v", err)
		// Don't fail the entire upgrade if version file write fails
	} else {
		logger.Infof("Saved current version %s to %s", versionInfo.Version, versionFilePath)
	}

	// Step 5: Write all rules from database to disk
	if err := w.writeAllRulesToDisk(); err != nil {
		logger.Errorf("Failed to write rules to disk: %v", err)
		// Don't fail the entire upgrade if write fails
	}
	logger.Info("Written all rules from database to disk!")

	// Step 6: Generate version.txt file
	if err := w.generateVersionFile(); err != nil {
		logger.Errorf("Failed to generate version file: %v", err)
		// Don't fail the entire upgrade if version file generation fails
	}

	// Step 7: Send reload signal to engine
	if err := w.sendReloadSignalToEngine(); err != nil {
		logger.Errorf("Failed to send reload signal to engine: %v", err)
		// Don't fail the entire upgrade if signal send fails
	}
	logger.Info("Send reload signal to engine done!")

	return descPath, extractDir, nil
}

// RuleUploadInfo represents rule information for upload descriptor
type RuleUploadInfo struct {
	ID           string `json:"id"`
	UpdateTm     int64  `json:"update_tm"`
	MD5          string `json:"md5"`
	DetectionMD5 string `json:"detection_md5"`
	Action       string `json:"action"` // "new" or "update"
}

// RuleUploadDescriptor represents the desc.json for upload package
type RuleUploadDescriptor struct {
	Version       string           `json:"version"`
	Flow          []RuleUploadInfo `json:"flow"`
	PktLog        []RuleUploadInfo `json:"pktlog"`
	WinLog        []RuleUploadInfo `json:"winlog"`
	ClientVersion string           `json:"client_version,omitempty"`
	ClientTrait   string           `json:"client_trait,omitempty"`
}

// uploadLocalRules compares local rules with remote descriptor and uploads differences
func (w *Worker) uploadLocalRules(ctx context.Context, descPath, extractDir, upgradeSrv, rulesPath string, upgradeProxy bool, httpProxy string) error {
	if upgradeSrv == "" {
		logger.Info("UpgradeSrv not configured, skipping rule upload")
		return nil
	}

	// Parse desc.json to get remote rule metadata
	data, err := os.ReadFile(descPath)
	if err != nil {
		return fmt.Errorf("failed to read desc.json: %w", err)
	}

	var desc RuleDescriptor
	if err := json.Unmarshal(data, &desc); err != nil {
		return fmt.Errorf("failed to parse desc.json: %w", err)
	}

	// Create a map of remote rules for quick lookup
	remoteRules := make(map[string]RuleMetadata)
	for _, meta := range desc.Flow {
		remoteRules[meta.ID] = meta
	}
	for _, meta := range desc.PktLog {
		remoteRules[meta.ID] = meta
	}
	for _, meta := range desc.WinLog {
		remoteRules[meta.ID] = meta
	}

	// Collect rules to upload
	uploadDesc := RuleUploadDescriptor{
		Version:       fmt.Sprintf("%d", time.Now().Unix()),
		Flow:          []RuleUploadInfo{},
		PktLog:        []RuleUploadInfo{},
		WinLog:        []RuleUploadInfo{},
		ClientVersion: version.GetBuildVersion(),
		ClientTrait:   license.GetTrait(),
	}

	// Check and collect flow rules
	flowRules, err := w.collectFlowRulesToUpload(ctx, remoteRules)
	if err != nil {
		logger.Errorf("Failed to collect flow rules: %v", err)
	} else {
		uploadDesc.Flow = flowRules
	}

	// Check and collect activity rules (winlog/pktlog)
	winlogRules, pktlogRules, err := w.collectActivityRulesToUpload(ctx, remoteRules)
	if err != nil {
		logger.Errorf("Failed to collect activity rules: %v", err)
	} else {
		uploadDesc.WinLog = winlogRules
		uploadDesc.PktLog = pktlogRules
	}

	totalRules := len(uploadDesc.Flow) + len(uploadDesc.WinLog) + len(uploadDesc.PktLog)
	if totalRules == 0 {
		logger.Info("No local-only or updated rules found, skipping upload")
		return nil
	}

	logger.Infof("Found %d rules to upload (flow: %d, winlog: %d, pktlog: %d)",
		totalRules, len(uploadDesc.Flow), len(uploadDesc.WinLog), len(uploadDesc.PktLog))

	// Create upload package
	uploadZipPath := filepath.Join(rulesPath, fmt.Sprintf("upload_%s.zip", uploadDesc.Version))
	if err := w.createUploadPackage(ctx, &uploadDesc, uploadZipPath, rulesPath); err != nil {
		return fmt.Errorf("failed to create upload package: %w", err)
	}

	// Upload to remote server
	if err := w.uploadPackageToRemote(ctx, upgradeSrv, uploadZipPath, upgradeProxy, httpProxy); err != nil {
		return fmt.Errorf("failed to upload package: %w", err)
	}

	logger.Infof("Successfully uploaded %d rules to remote server", totalRules)

	// Clean up upload package
	os.Remove(uploadZipPath)

	return nil
}

// collectFlowRulesToUpload collects flow rules that need to be uploaded
func (w *Worker) collectFlowRulesToUpload(ctx context.Context, remoteRules map[string]RuleMetadata) ([]RuleUploadInfo, error) {
	var uploadList []RuleUploadInfo

	// Query all flow rules from database
	var flowRules []model.AlertRule
	if err := w.env.MongoCli.FindAll((&model.AlertRule{}).CollectName(), bson.M{}, &flowRules); err != nil {
		return nil, fmt.Errorf("failed to query flow rules: %w", err)
	}

	for _, rule := range flowRules {
		// Calculate detection MD5 from the detection field
		detectionBytes, err := json.Marshal(rule.Detection)
		if err != nil {
			logger.Warnf("Failed to marshal detection for rule %s: %v", rule.ID, err)
			continue
		}
		localDetectionMD5 := calculateStringMD5(string(detectionBytes))

		// Calculate full rule MD5
		ruleBytes, err := json.Marshal(rule)
		if err != nil {
			logger.Warnf("Failed to marshal rule %s: %v", rule.ID, err)
			continue
		}
		ruleMD5 := calculateStringMD5(string(ruleBytes))

		// Check if rule exists in remote
		remoteMeta, exists := remoteRules[rule.ID]
		action := ""

		if !exists {
			// Rule only exists locally - new rule
			action = "new"
			logger.Infof("Flow rule %s exists only locally (new)", rule.ID)
		} else if remoteMeta.DetectionMD5 != localDetectionMD5 {
			// Rule exists but detection differs - updated rule
			action = "update"
			logger.Infof("Flow rule %s has been updated locally", rule.ID)
		}

		if action != "" {
			uploadList = append(uploadList, RuleUploadInfo{
				ID:           rule.ID,
				UpdateTm:     rule.UpdateTm.Unix(),
				MD5:          ruleMD5,
				DetectionMD5: localDetectionMD5,
				Action:       action,
			})
		}
	}

	return uploadList, nil
}

// collectActivityRulesToUpload collects activity rules (winlog/pktlog) that need to be uploaded
func (w *Worker) collectActivityRulesToUpload(ctx context.Context, remoteRules map[string]RuleMetadata) ([]RuleUploadInfo, []RuleUploadInfo, error) {
	var winlogList []RuleUploadInfo
	var pktlogList []RuleUploadInfo

	// Query all activity rules from database
	var activityRules []model.AlertActivityRule
	if err := w.env.MongoCli.FindAll((&model.AlertActivityRule{}).CollectName(), bson.M{}, &activityRules); err != nil {
		return nil, nil, fmt.Errorf("failed to query activity rules: %w", err)
	}

	for _, rule := range activityRules {
		// Calculate detection MD5 from the detection field
		detectionBytes, err := json.Marshal(rule.Detection)
		if err != nil {
			logger.Warnf("Failed to marshal detection for rule %s: %v", rule.ID, err)
			continue
		}
		localDetectionMD5 := calculateStringMD5(string(detectionBytes))

		// Calculate full rule MD5
		ruleBytes, err := json.Marshal(rule)
		if err != nil {
			logger.Warnf("Failed to marshal rule %s: %v", rule.ID, err)
			continue
		}
		ruleMD5 := calculateStringMD5(string(ruleBytes))

		// Check if rule exists in remote
		remoteMeta, exists := remoteRules[rule.ID]
		action := ""

		if !exists {
			// Rule only exists locally - new rule
			action = "new"
			logger.Infof("Activity rule %s exists only locally (new)", rule.ID)
		} else if remoteMeta.DetectionMD5 != localDetectionMD5 {
			// Rule exists but detection differs - updated rule
			action = "update"
			logger.Infof("Activity rule %s has been updated locally", rule.ID)
		}

		if action != "" {
			uploadInfo := RuleUploadInfo{
				ID:           rule.ID,
				UpdateTm:     rule.UpdateTm.Unix(),
				MD5:          ruleMD5,
				DetectionMD5: localDetectionMD5,
				Action:       action,
			}

			// Determine rule type based on logsource
			if strings.Contains(rule.Logsource, "winlog") || strings.Contains(rule.Logsource, "windows") {
				winlogList = append(winlogList, uploadInfo)
			} else {
				pktlogList = append(pktlogList, uploadInfo)
			}
		}
	}

	return winlogList, pktlogList, nil
}

// calculateFileMD5 calculates MD5 hash of a file
func calculateFileMD5(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := md5.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// calculateStringMD5 calculates MD5 hash of a string
func calculateStringMD5(s string) string {
	hash := md5.New()
	hash.Write([]byte(s))
	return hex.EncodeToString(hash.Sum(nil))
}

// extractAndValidateZIP extracts the ZIP file and validates structure
func (w *Worker) extractAndValidateZIP(zipPath, rulesPath string) (string, error) {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("failed to open ZIP: %w", err)
	}
	defer r.Close()

	// Extract files
	var extractDir string
	for _, f := range r.File {
		// Get the top-level directory name
		if extractDir == "" {
			parts := strings.Split(f.Name, string(os.PathSeparator))
			if len(parts) > 0 {
				extractDir = filepath.Join(rulesPath, parts[0])
			}
		}

		fpath := filepath.Join(rulesPath, f.Name)

		// Check for ZipSlip vulnerability
		if !strings.HasPrefix(fpath, filepath.Clean(rulesPath)+string(os.PathSeparator)) {
			return "", fmt.Errorf("illegal file path: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		// Create parent directories
		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return "", err
		}

		// Extract file
		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return "", err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return "", err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()

		if err != nil {
			return "", err
		}
	}

	// Validate structure
	if extractDir == "" {
		return "", fmt.Errorf("no top-level directory found in ZIP")
	}

	requiredPaths := []string{
		filepath.Join(extractDir, "desc.json"),
		filepath.Join(extractDir, "flow"),
		filepath.Join(extractDir, "pktlog"),
		filepath.Join(extractDir, "winlog"),
	}

	for _, path := range requiredPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return "", fmt.Errorf("required path not found: %s", path)
		}
	}

	return extractDir, nil
}

// updateRulesFromDescriptor reads desc.json and updates rules in database
func (w *Worker) updateRulesFromDescriptor(ctx context.Context, descPath, extractDir string) error {
	// Parse desc.json
	data, err := os.ReadFile(descPath)
	if err != nil {
		return fmt.Errorf("failed to read desc.json: %w", err)
	}

	var desc RuleDescriptor
	if err := json.Unmarshal(data, &desc); err != nil {
		return fmt.Errorf("failed to parse desc.json: %w", err)
	}

	// Process rules in order: pktlog, winlog, flow
	logger.Infof("Processing %d pktlog rules", len(desc.PktLog))
	for _, meta := range desc.PktLog {
		if err := w.updateActivityRule(ctx, meta, filepath.Join(extractDir, "pktlog"), common.RuleTypePktLog); err != nil {
			logger.Errorf("Failed to update pktlog rule %s: %v", meta.ID, err)
		}
	}

	logger.Infof("Processing %d winlog rules", len(desc.WinLog))
	for _, meta := range desc.WinLog {
		if err := w.updateActivityRule(ctx, meta, filepath.Join(extractDir, "winlog"), common.RuleTypeWinLog); err != nil {
			logger.Errorf("Failed to update winlog rule %s: %v", meta.ID, err)
		}
	}

	logger.Infof("Processing %d flow rules", len(desc.Flow))
	for _, meta := range desc.Flow {
		if err := w.updateFlowRule(ctx, meta, filepath.Join(extractDir, "flow")); err != nil {
			logger.Errorf("Failed to update flow rule %s: %v", meta.ID, err)
		}
	}

	return nil
}

// updateActivityRule updates or inserts an activity rule (winlog/pktlog)
func (w *Worker) updateActivityRule(ctx context.Context, meta RuleMetadata, rulesDir, ruleType string) error {
	// Find the rule file
	ruleFile, err := w.findRuleFile(meta, rulesDir)
	if err != nil {
		return fmt.Errorf("failed to find rule file: %w", err)
	}

	// Parse YAML rule
	data, err := os.ReadFile(ruleFile)
	if err != nil {
		return fmt.Errorf("failed to read rule file: %w", err)
	}

	// Parse directly into model.AlertActivityRule
	// The custom UnmarshalYAML method handles level and logsource conversion
	var rule model.AlertActivityRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return fmt.Errorf("failed to parse YAML rule: %w", err)
	}

	// Parse date/modified fields from YAML
	createTm := parseRuleDate(rule.RuleDate)
	updateTm := parseRuleDate(rule.RuleModified)

	// Check if rule exists
	var existingRule model.AlertActivityRule
	_, exists := w.env.MongoCli.FindOne(existingRule.CollectName(), bson.M{"_id": rule.ID}, &existingRule)

	if exists {
		// Update existing rule
		update := bson.M{
			"title":         rule.Title,
			"description":   rule.Description,
			"level":         rule.Level,
			"status":        rule.Status,
			"tags":          rule.Tags,
			"logsource":     rule.Logsource,
			"detection":     rule.Detection,
			"rdx_key":       rule.RdxKey,
			"fields":        rule.Fields,
			"unique_fields": rule.UniqueFields,
			"author":        rule.Author,
			"references":    rule.References,
			"update_tm":     updateTm,
		}

		if err := w.env.MongoCli.UpdateById(existingRule.CollectName(), rule.ID, update); err != nil {
			return fmt.Errorf("failed to update rule: %w", err)
		}
		logger.Debugf("Updated activity rule: %s", rule.ID)
	} else {
		// Insert new rule
		rule.CreateTm = createTm
		rule.UpdateTm = updateTm

		if err := w.env.MongoCli.Insert(rule.CollectName(), &rule); err != nil {
			return fmt.Errorf("failed to insert rule: %w", err)
		}
		logger.Debugf("Inserted new activity rule: %s", rule.ID)
	}

	return nil
}

// updateFlowRule updates or inserts a flow rule
func (w *Worker) updateFlowRule(ctx context.Context, meta RuleMetadata, rulesDir string) error {
	// Find the rule file
	ruleFile, err := w.findRuleFile(meta, rulesDir)
	if err != nil {
		return fmt.Errorf("failed to find rule file: %w", err)
	}

	// Parse YAML rule
	data, err := os.ReadFile(ruleFile)
	if err != nil {
		return fmt.Errorf("failed to read rule file: %w", err)
	}

	// Parse directly into model.AlertRule
	// The custom UnmarshalYAML method handles level and logsource conversion
	var rule model.AlertRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return fmt.Errorf("failed to parse YAML rule: %w", err)
	}

	// Parse date/modified fields from YAML
	createTm := parseRuleDate(rule.RuleDate)
	updateTm := parseRuleDate(rule.RuleModified)

	// Check if rule exists
	var existingRule model.AlertRule
	_, exists := w.env.MongoCli.FindOne(existingRule.CollectName(), bson.M{"_id": rule.ID}, &existingRule)

	if exists {
		// Update existing rule
		update := bson.M{
			"title":         rule.Title,
			"description":   rule.Description,
			"level":         rule.Level,
			"enable":        rule.Enable,
			"status":        rule.Status,
			"tags":          rule.Tags,
			"logsource":     rule.Logsource,
			"detection":     rule.Detection,
			"type":          rule.Type,
			"references":    rule.References,
			"suggestion":    rule.Suggestion,
			"author":        rule.Author,
			"auto_block":    rule.AutoBlock,
			"attack_flow":   rule.AttackFlow,
			"unique_filter": rule.UniqueFilter,
			"update_tm":     updateTm,
		}

		if err := w.env.MongoCli.UpdateById(existingRule.CollectName(), rule.ID, update); err != nil {
			return fmt.Errorf("failed to update flow rule: %w", err)
		}
		logger.Debugf("Updated flow rule: %s", rule.ID)
	} else {
		// Insert new rule
		rule.Enable = true // Default to enabled
		rule.CreateTm = createTm
		rule.UpdateTm = updateTm

		if err := w.env.MongoCli.Insert(rule.CollectName(), &rule); err != nil {
			return fmt.Errorf("failed to insert flow rule: %w", err)
		}
		logger.Debugf("Inserted new flow rule: %s", rule.ID)
	}

	return nil
}

// findRuleFile finds the rule file by metadata in the given directory
func (w *Worker) findRuleFile(meta RuleMetadata, rulesDir string) (string, error) {
	// If filename is provided in metadata, use it directly
	if meta.Filename != "" {
		filePath := filepath.Join(rulesDir, meta.Filename)
		if _, err := os.Stat(filePath); err == nil {
			return filePath, nil
		}
		// If specified file doesn't exist, fall back to glob search
		logger.Warnf("Specified filename %s not found, falling back to glob search for ID: %s", meta.Filename, meta.ID)
	}

	// Fallback: Search for files matching pattern *-<ruleID>.yml
	files, err := filepath.Glob(filepath.Join(rulesDir, fmt.Sprintf("*-%s.yml", meta.ID)))
	if err != nil {
		return "", err
	}

	if len(files) == 0 {
		return "", fmt.Errorf("no rule file found for ID: %s", meta.ID)
	}

	return files[0], nil
}

// parseRuleDate parses date string from YAML rule (format: YYYY/MM/DD or YYYY-MM-DD)
// Returns parsed time or current time if parsing fails
func parseRuleDate(dateStr string) time.Time {
	if dateStr == "" {
		return time.Now()
	}

	// Try common date formats
	formats := []string{
		"2006/01/02",
		"2006-01-02",
		"2006/01/02 15:04:05",
		"2006-01-02 15:04:05",
		time.RFC3339,
	}

	for _, format := range formats {
		if t, err := time.Parse(format, dateStr); err == nil {
			return t
		}
	}

	// If parsing fails, log warning and return current time
	logger.Warnf("Failed to parse rule date '%s', using current time", dateStr)
	return time.Now()
}

// createUploadPackage creates a ZIP package with rules and desc.json
func (w *Worker) createUploadPackage(ctx context.Context, uploadDesc *RuleUploadDescriptor, zipPath, rulesPath string) error {
	// Create temporary directory for organizing upload files
	tmpDir := filepath.Join(rulesPath, fmt.Sprintf("upload_tmp_%s", uploadDesc.Version))
	if err := os.MkdirAll(tmpDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create subdirectories
	flowDir := filepath.Join(tmpDir, "flow")
	pktlogDir := filepath.Join(tmpDir, "pktlog")
	winlogDir := filepath.Join(tmpDir, "winlog")

	os.MkdirAll(flowDir, 0755)
	os.MkdirAll(pktlogDir, 0755)
	os.MkdirAll(winlogDir, 0755)

	// Export flow rules to YAML files
	for _, ruleInfo := range uploadDesc.Flow {
		if err := w.exportFlowRuleToYAML(ctx, ruleInfo.ID, flowDir); err != nil {
			logger.Errorf("Failed to export flow rule %s: %v", ruleInfo.ID, err)
		}
	}

	// Export pktlog rules to YAML files
	for _, ruleInfo := range uploadDesc.PktLog {
		if err := w.exportActivityRuleToYAML(ctx, ruleInfo.ID, pktlogDir); err != nil {
			logger.Errorf("Failed to export pktlog rule %s: %v", ruleInfo.ID, err)
		}
	}

	// Export winlog rules to YAML files
	for _, ruleInfo := range uploadDesc.WinLog {
		if err := w.exportActivityRuleToYAML(ctx, ruleInfo.ID, winlogDir); err != nil {
			logger.Errorf("Failed to export winlog rule %s: %v", ruleInfo.ID, err)
		}
	}

	// Create desc.json
	descData, err := json.MarshalIndent(uploadDesc, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal descriptor: %w", err)
	}

	descPath := filepath.Join(tmpDir, "desc.json")
	if err := os.WriteFile(descPath, descData, 0644); err != nil {
		return fmt.Errorf("failed to write desc.json: %w", err)
	}

	// Create ZIP file
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Add all files to ZIP
	return filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			return nil
		}

		// Get relative path
		relPath, err := filepath.Rel(tmpDir, path)
		if err != nil {
			return err
		}

		// Create ZIP entry
		writer, err := zipWriter.Create(relPath)
		if err != nil {
			return err
		}

		// Read file content
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		// Write to ZIP
		_, err = writer.Write(data)
		return err
	})
}

// exportFlowRuleToYAML exports a flow rule from DB to YAML file
func (w *Worker) exportFlowRuleToYAML(ctx context.Context, ruleID, outputDir string) error {
	var rule model.AlertRule
	_, exists := w.env.MongoCli.FindOne(rule.CollectName(), bson.M{"_id": ruleID}, &rule)
	if !exists {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	yamlData, err := yaml.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	// Generate filename (format: XXXX-XXXX.yml)
	filePath := filepath.Join(outputDir, fmt.Sprintf("%s.yml", rule.ID))

	return os.WriteFile(filePath, yamlData, 0644)
}

// exportActivityRuleToYAML exports an activity rule from DB to YAML file
func (w *Worker) exportActivityRuleToYAML(ctx context.Context, ruleID, outputDir string) error {
	var rule model.AlertActivityRule
	_, exists := w.env.MongoCli.FindOne(rule.CollectName(), bson.M{"_id": ruleID}, &rule)
	if !exists {
		return fmt.Errorf("rule not found: %s", ruleID)
	}

	// Marshal to YAML
	yamlData, err := yaml.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %w", err)
	}

	// Generate filename (format: XXXX-XXXX.yml)
	filePath := filepath.Join(outputDir, fmt.Sprintf("%s.yml", rule.ID))

	return os.WriteFile(filePath, yamlData, 0644)
}

// riskLevelToString converts level integer to string
func riskLevelToString(level int32) string {
	if val, ok := common.RiskLeveStrlMap[int(level)]; ok {
		return val
	}
	return common.RiskLeveStrlMap[common.RiskLevelInfo]
}

// uploadPackageToRemote uploads the ZIP package to remote server
func (w *Worker) uploadPackageToRemote(ctx context.Context, upgradeSrv, zipPath string, upgradeProxy bool, httpProxy string) error {
	// Ensure proper URL joining, handle trailing slash
	baseURL := strings.TrimSuffix(upgradeSrv, "/")
	requestURL := fmt.Sprintf("%s/rule/peer/upload", baseURL)

	// Open the ZIP file
	file, err := os.Open(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip file: %w", err)
	}
	defer file.Close()

	// Get file info for content length
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat zip file: %w", err)
	}

	// Create HTTP request with multipart form
	var requestBody io.Reader = file
	contentType := "application/zip"

	req, err := http.NewRequestWithContext(ctx, "POST", requestURL, requestBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)
	req.ContentLength = fileInfo.Size()

	// Create HTTP client with proxy support
	var client *http.Client
	if upgradeProxy && httpProxy != "" {
		client = netutil.NewHTTPClientWithProxy(httpProxy, 300) // 5 minutes timeout
	} else {
		client = netutil.NewHTTPClient(300)
	}

	logger.Infof("Uploading rule package to %s (size: %d bytes)", requestURL, fileInfo.Size())
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to upload: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return httpStatusError("upload rules", requestURL, resp)
	}

	logger.Info("Rule package uploaded successfully")
	return nil
}

func httpStatusError(action, requestURL string, resp *http.Response) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2048))
	if err != nil {
		return fmt.Errorf("%s request(%s) failed with status %d and unreadable body: %w", action, requestURL, resp.StatusCode, err)
	}

	msg := strings.TrimSpace(string(body))
	if msg == "" {
		return fmt.Errorf("%s request(%s) failed with status %d", action, requestURL, resp.StatusCode)
	}

	return fmt.Errorf("%s request(%s) failed with status %d: %s", action, requestURL, resp.StatusCode, msg)
}

// writeAlertRuleToFile writes an AlertRule to a YAML file
func (w *Worker) writeAlertRuleToFile(rule *model.AlertRule) error {
	// Ensure directory exists
	ruleDir := filepath.Join(common.ROOT_PATH, "rules", common.RuleTypeFlow)
	if err := os.MkdirAll(ruleDir, 0755); err != nil {
		return fmt.Errorf("failed to create rule directory: %v", err)
	}

	// Marshal to YAML
	data, err := yaml.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule to YAML: %v", err)
	}

	// Write to file
	filename := filepath.Join(ruleDir, fmt.Sprintf("%s.yml", rule.ID))
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write rule file: %v", err)
	}

	logger.Debugf("Wrote alert rule to %s", filename)
	return nil
}

// writeActivityRuleToFile writes an ActivityRule to a YAML file
func (w *Worker) writeActivityRuleToFile(rule *model.AlertActivityRule) error {
	// Determine rule type from ID prefix (winlog-*, pktlog-*)
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

	// Marshal to YAML
	data, err := yaml.Marshal(rule)
	if err != nil {
		return fmt.Errorf("failed to marshal rule to YAML: %v", err)
	}

	// Write to file
	filename := filepath.Join(ruleDir, fmt.Sprintf("%s.yml", rule.ID))
	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write rule file: %v", err)
	}

	logger.Debugf("Wrote activity rule to %s", filename)
	return nil
}

// writeAllRulesToDisk synchronizes all rules from database to disk files
func (w *Worker) writeAllRulesToDisk() error {
	logger.Info("Syncing all rules from database to disk...")

	// Step 1: Clean up old rule files
	ruleTypes := []string{common.RuleTypeFlow, common.RuleTypeWinLog, common.RuleTypePktLog}
	for _, ruleType := range ruleTypes {
		ruleDir := filepath.Join(common.ROOT_PATH, "rules", ruleType)
		if err := w.cleanupRuleDirectory(ruleDir); err != nil {
			logger.Errorf("Failed to cleanup rule directory %s: %v", ruleDir, err)
			// Continue even if cleanup fails
		}
	}

	// Step 2: Sync alert rules (flow rules)
	var alertRules []model.AlertRule
	if err := w.env.MongoCli.FindAll((&model.AlertRule{}).CollectName(), bson.M{}, &alertRules); err != nil {
		return fmt.Errorf("failed to query alert rules: %w", err)
	}

	for _, rule := range alertRules {
		if err := w.writeAlertRuleToFile(&rule); err != nil {
			logger.Errorf("Failed to write alert rule %s: %v", rule.ID, err)
		}
	}

	// Step 3: Sync activity rules (winlog/pktlog rules)
	var activityRules []model.AlertActivityRule
	if err := w.env.MongoCli.FindAll((&model.AlertActivityRule{}).CollectName(), bson.M{}, &activityRules); err != nil {
		return fmt.Errorf("failed to query activity rules: %w", err)
	}

	for _, rule := range activityRules {
		if err := w.writeActivityRuleToFile(&rule); err != nil {
			logger.Errorf("Failed to write activity rule %s: %v", rule.ID, err)
		}
	}

	logger.Infof("Synced %d alert rules and %d activity rules to disk", len(alertRules), len(activityRules))
	return nil
}

// cleanupRuleDirectory removes all .yml and .yml files from a rule directory
func (w *Worker) cleanupRuleDirectory(ruleDir string) error {
	// Check if directory exists
	if _, err := os.Stat(ruleDir); os.IsNotExist(err) {
		logger.Debugf("Rule directory %s does not exist, skipping cleanup", ruleDir)
		return nil
	}

	// Read all files in directory
	entries, err := os.ReadDir(ruleDir)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}

	// Delete all .yml and .yml files
	deletedCount := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		if strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml") {
			filePath := filepath.Join(ruleDir, filename)
			if err := os.Remove(filePath); err != nil {
				logger.Warnf("Failed to delete old rule file %s: %v", filePath, err)
			} else {
				deletedCount++
			}
		}
	}

	if deletedCount > 0 {
		logger.Infof("Cleaned up %d old rule files from %s", deletedCount, ruleDir)
	}

	return nil
}

// generateVersionFile creates a version.txt file with current timestamp and build time
func (w *Worker) generateVersionFile() error {
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

// sendReloadSignalToEngine sends a reload signal to engine via Redis pub/sub
func (w *Worker) sendReloadSignalToEngine() error {

	// Publish reload message to Redis channel
	message := fmt.Sprintf("reload:%d", time.Now().Unix())
	err := w.env.RedisCli.Publish(context.Background(), cache.EngineReloadChannel, message).Err()
	if err != nil {
		logger.Errorf("Failed to publish reload signal to engine: %v", err)
		return err
	}

	logger.Infof("Published reload signal to engine via Redis channel '%s'", cache.EngineReloadChannel)
	return nil
}
