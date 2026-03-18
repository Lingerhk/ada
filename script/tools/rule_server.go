//go:build tools

package main

import (
	"ada/backend/model"
	"ada/infra/mongo"
	"archive/zip"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	logger "github.com/sirupsen/logrus"
	"go.mongodb.org/mongo-driver/v2/bson"
	"gopkg.in/yaml.v3"
)

const (
	DefaultPort          = 8080
	DefaultRulesDir      = "/home/adadmin/adaegis/ada/engine/rules"
	DefaultPackageDir    = "./rule_packages"
	DefaultUploadDir     = "uploads" // 上传文件存储子目录
	DefaultLogDir        = "logs"    // 日志文件存储子目录
	DefaultMaxConcurrent = 100       // 最大并发连接数
	DefaultReadTimeout   = 30        // 读超时（秒）
	DefaultWriteTimeout  = 300       // 写超时（秒），大文件需要更长时间
	DefaultIdleTimeout   = 120       // 空闲超时（秒）
	DefaultMaxUploadSize = 64        // 最大上传大小（MB）
	MaxLogQueueSize      = 1000      // 日志队列最大大小

	// MongoDB defaults
	DefaultMongoHost   = "192.168.7.2:27017"
	DefaultMongoUser   = "user_ada"
	DefaultMongoPasswd = "XEl44B4p3hFurztFMo38"
	DefaultMongoDbName = "db_ada"
)

// RuleVersionInfo represents the version information in latest.json
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

// UploadDescriptor extends RuleDescriptor with client info
type UploadDescriptor struct {
	RuleDescriptor
	ClientVersion string `json:"client_version,omitempty"`
	ClientTrait   string `json:"client_trait,omitempty"`
}

// DownloadLog represents a download record
type DownloadLog struct {
	Timestamp     time.Time `json:"timestamp"`
	RemoteIP      string    `json:"remote_ip"`
	ClientVersion string    `json:"client_version"`
	ClientTrait   string    `json:"client_trait"`
	PackageFile   string    `json:"package_file"`
}

// Server represents the rule server
type Server struct {
	port           int
	rulesDir       string
	packageDir     string
	uploadDir      string         // 上传文件存储目录
	logDir         string         // 日志文件存储目录
	logQueue       chan any       // 异步日志队列
	logWg          sync.WaitGroup // 等待日志写入完成
	semaphore      chan struct{}  // 并发控制信号量
	shutdownCtx    context.Context
	shutdownCancel context.CancelFunc
	logFileMutex   sync.Mutex      // 日志文件写入锁
	mongoCli       mongo.DBAdaptor // MongoDB client
	mongoHost      string
	mongoUser      string
	mongoPasswd    string
	mongoDbName    string
}

func main() {
	var (
		port          int
		rulesDir      string
		packageDir    string
		genPackage    bool
		maxConcurrent int
		logLevel      string
		mongoHost     string
		mongoUser     string
		mongoPasswd   string
		mongoDbName   string
	)

	flag.IntVar(&port, "port", DefaultPort, "Server port")
	flag.StringVar(&rulesDir, "rules", DefaultRulesDir, "Rules directory path")
	flag.StringVar(&packageDir, "packages", DefaultPackageDir, "Package storage directory")
	flag.BoolVar(&genPackage, "gen", false, "Generate rule package from MongoDB and exit")
	flag.IntVar(&maxConcurrent, "max-concurrent", DefaultMaxConcurrent, "Maximum concurrent connections")
	flag.StringVar(&logLevel, "log-level", "debug", "Log level (trace, debug, info, warn, error, fatal, panic)")
	flag.StringVar(&mongoHost, "mongo-host", DefaultMongoHost, "MongoDB host")
	flag.StringVar(&mongoUser, "mongo-user", DefaultMongoUser, "MongoDB user")
	flag.StringVar(&mongoPasswd, "mongo-passwd", DefaultMongoPasswd, "MongoDB password")
	flag.StringVar(&mongoDbName, "mongo-db", DefaultMongoDbName, "MongoDB database name")

	flag.Parse()

	logger.SetFormatter(&logger.TextFormatter{
		FullTimestamp: true,
	})

	// Parse and set log level
	level, err := logger.ParseLevel(logLevel)
	if err != nil {
		logger.Warnf("Invalid log level '%s', using default 'debug'", logLevel)
		level = logger.InfoLevel
	}
	logger.SetLevel(level)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup directory paths
	uploadDir := filepath.Join(packageDir, DefaultUploadDir)
	logDir := filepath.Join(packageDir, DefaultLogDir)

	server := &Server{
		port:           port,
		rulesDir:       rulesDir,
		packageDir:     packageDir,
		uploadDir:      uploadDir,
		logDir:         logDir,
		logQueue:       make(chan any, MaxLogQueueSize),
		semaphore:      make(chan struct{}, maxConcurrent),
		shutdownCtx:    ctx,
		shutdownCancel: cancel,
		mongoHost:      mongoHost,
		mongoUser:      mongoUser,
		mongoPasswd:    mongoPasswd,
		mongoDbName:    mongoDbName,
	}

	// Initialize MongoDB connection
	if err := server.initMongoDB(); err != nil {
		logger.Fatalf("Failed to initialize MongoDB: %v", err)
	}
	defer func() {
		if server.mongoCli != nil {
			server.mongoCli.Disconnect(server.shutdownCtx)
		}
	}()

	// Ensure directories exist
	for _, dir := range []string{packageDir, uploadDir, logDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			logger.Fatalf("Failed to create directory %s: %v", dir, err)
		}
	}

	if genPackage {
		// Generate package and exit
		logger.Info("Generating rule package...")
		if err := server.generateRulePackage(); err != nil {
			logger.Fatalf("Failed to generate rule package: %v", err)
		}
		logger.Info("Rule package generated successfully")
		return
	}

	// Start async log writer
	server.logWg.Add(1)
	go server.asyncLogWriter()

	// Start HTTP server
	logger.Infof("Starting rule server on port %d", port)
	logger.Infof("Rules directory: %s", rulesDir)
	logger.Infof("Package directory: %s", packageDir)
	logger.Infof("Max concurrent connections: %d", maxConcurrent)
	logger.Infof("Log level: %s", logger.GetLevel())

	// Create HTTP server with timeouts and limits
	mux := http.NewServeMux()
	mux.HandleFunc("/rule/version/latest.json", server.rateLimitMiddleware(server.handleLatestVersion))
	mux.HandleFunc("/rule/package/latest.zip", server.rateLimitMiddleware(server.handleLatestPackage))
	mux.HandleFunc("/rule/peer/upload", server.rateLimitMiddleware(server.handleUpload))

	httpServer := &http.Server{
		Addr:           fmt.Sprintf("0.0.0.0:%d", port),
		Handler:        mux,
		ReadTimeout:    time.Duration(DefaultReadTimeout) * time.Second,
		WriteTimeout:   time.Duration(DefaultWriteTimeout) * time.Second,
		IdleTimeout:    time.Duration(DefaultIdleTimeout) * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Graceful shutdown
	go func() {
		<-ctx.Done()
		logger.Info("Shutting down server...")

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			logger.Errorf("Server shutdown error: %v", err)
		}

		// Close log queue and wait for flush
		close(server.logQueue)
		server.logWg.Wait()
		logger.Info("Server stopped gracefully")
	}()

	logger.Info("Server is ready to handle requests")
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Fatalf("Server failed: %v", err)
	}
}

// initMongoDB initializes the MongoDB connection
func (s *Server) initMongoDB() error {
	mongoCli := mongo.NewMongoSession()
	MongoURL := fmt.Sprintf("mongodb://%s:%s@%s/?authSource=%s",
		s.mongoUser, s.mongoPasswd, s.mongoHost, s.mongoDbName)

	err := mongoCli.Connect(s.shutdownCtx, MongoURL, s.mongoDbName)
	if err != nil {
		return fmt.Errorf("failed to connect to MongoDB: %w", err)
	}

	s.mongoCli = mongoCli
	logger.Infof("Connected to MongoDB at %s, database: %s", s.mongoHost, s.mongoDbName)
	return nil
}

// rateLimitMiddleware implements rate limiting using semaphore
func (s *Server) rateLimitMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case s.semaphore <- struct{}{}:
			defer func() { <-s.semaphore }()
			next(w, r)
		case <-time.After(5 * time.Second):
			http.Error(w, "Server is busy, please try again later", http.StatusServiceUnavailable)
			logger.Warnf("Rate limit exceeded for %s from %s", r.URL.Path, r.RemoteAddr)
		}
	}
}

// asyncLogWriter writes logs asynchronously from the queue
func (s *Server) asyncLogWriter() {
	defer s.logWg.Done()

	for logEntry := range s.logQueue {
		switch entry := logEntry.(type) {
		case DownloadLog:
			s.writeDownloadLog(entry)
		case map[string]any:
			if logType, ok := entry["_log_type"].(string); ok {
				delete(entry, "_log_type")
				var logPath string
				if logType == "download" {
					logPath = filepath.Join(s.logDir, "downloads.log")
				} else {
					logPath = filepath.Join(s.logDir, "uploads.log")
				}
				s.appendLogSync(logPath, entry)
			}
		}
	}
}

// writeDownloadLog writes download log entry
func (s *Server) writeDownloadLog(log DownloadLog) {
	logEntry := map[string]any{
		"timestamp":      log.Timestamp.Format(time.RFC3339),
		"remote_ip":      log.RemoteIP,
		"client_version": log.ClientVersion,
		"client_trait":   log.ClientTrait,
		"package_file":   log.PackageFile,
	}

	logPath := filepath.Join(s.logDir, "downloads.log")
	s.appendLogSync(logPath, logEntry)
}

// appendLogSync appends a log entry to file with mutex protection
func (s *Server) appendLogSync(logPath string, entry map[string]any) error {
	s.logFileMutex.Lock()
	defer s.logFileMutex.Unlock()

	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		logger.Errorf("Failed to open log file: %v", err)
		return err
	}
	defer f.Close()

	data, err := json.Marshal(entry)
	if err != nil {
		logger.Errorf("Failed to marshal log entry: %v", err)
		return err
	}

	_, err = f.WriteString(string(data) + "\n")
	if err != nil {
		logger.Errorf("Failed to write log: %v", err)
	}
	return err
}

// handleLatestVersion serves the latest.json file
func (s *Server) handleLatestVersion(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	latestJSON := filepath.Join(s.packageDir, "latest.json")
	if _, err := os.Stat(latestJSON); os.IsNotExist(err) {
		http.Error(w, "No rule package available", http.StatusNotFound)
		return
	}

	data, err := os.ReadFile(latestJSON)
	if err != nil {
		http.Error(w, "Failed to read version file", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// handleLatestPackage serves the latest.zip file and logs download info
func (s *Server) handleLatestPackage(w http.ResponseWriter, r *http.Request) {
	logger.Debugf("Request: %s %s from %s", r.Method, r.URL.Path, r.RemoteAddr)

	// Extract query parameters
	clientVersion := r.URL.Query().Get("v")
	clientTrait := r.URL.Query().Get("trait")

	// Queue download log asynchronously
	downloadLog := DownloadLog{
		Timestamp:     time.Now(),
		RemoteIP:      r.RemoteAddr,
		ClientVersion: clientVersion,
		ClientTrait:   clientTrait,
		PackageFile:   "latest.zip",
	}

	select {
	case s.logQueue <- downloadLog:
		// Log queued successfully
	default:
		logger.Warnf("Log queue full, dropping download log entry")
	}

	logger.Infof("Download: client_version=%s, trait=%s, ip=%s",
		clientVersion, clientTrait, r.RemoteAddr)

	latestZIP := filepath.Join(s.packageDir, "latest.zip")
	if _, err := os.Stat(latestZIP); os.IsNotExist(err) {
		http.Error(w, "No rule package available", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=latest.zip")
	http.ServeFile(w, r, latestZIP)
}

// handleUpload handles rule package uploads from peers
func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	logger.Infof("Upload request from %s", r.RemoteAddr)

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit upload size
	r.Body = http.MaxBytesReader(w, r.Body, DefaultMaxUploadSize*1024*1024)

	// Read the uploaded file
	file, _, err := r.FormFile("file")
	if err != nil {
		// Try reading as direct body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Failed to read upload", http.StatusBadRequest)
			return
		}

		// Save to upload directory
		timestamp := time.Now().Unix()
		uploadPath := filepath.Join(s.uploadDir, fmt.Sprintf("upload_%d.zip", timestamp))

		if err := os.WriteFile(uploadPath, body, 0644); err != nil {
			logger.Errorf("Failed to save upload: %v", err)
			http.Error(w, "Failed to save upload", http.StatusInternalServerError)
			return
		}

		logger.Infof("Uploaded package saved to: %s (size: %d bytes)", uploadPath, len(body))

		// Process the uploaded package
		if err := s.processUploadedPackage(uploadPath, r.RemoteAddr); err != nil {
			logger.Errorf("Failed to process uploaded package: %v", err)
		}

		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, "Upload successful: %s\n", filepath.Base(uploadPath))
		return
	}
	defer file.Close()

	// Save uploaded file to upload directory
	timestamp := time.Now().Unix()
	uploadPath := filepath.Join(s.uploadDir, fmt.Sprintf("upload_%d.zip", timestamp))

	dst, err := os.Create(uploadPath)
	if err != nil {
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer dst.Close()

	size, err := io.Copy(dst, file)
	if err != nil {
		http.Error(w, "Failed to save file", http.StatusInternalServerError)
		return
	}

	logger.Infof("Uploaded package saved to: %s (size: %d bytes)", uploadPath, size)

	// Process the uploaded package
	if err := s.processUploadedPackage(uploadPath, r.RemoteAddr); err != nil {
		logger.Errorf("Failed to process uploaded package: %v", err)
	}

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "Upload successful: %s\n", filepath.Base(uploadPath))
}

// processUploadedPackage extracts and logs information from uploaded package
func (s *Server) processUploadedPackage(zipPath, remoteAddr string) error {
	// Extract desc.json to read metadata
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("failed to open zip: %w", err)
	}
	defer r.Close()

	for _, f := range r.File {
		if f.Name == "desc.json" || strings.HasSuffix(f.Name, "/desc.json") {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("failed to open desc.json: %w", err)
			}
			defer rc.Close()

			data, err := io.ReadAll(rc)
			if err != nil {
				return fmt.Errorf("failed to read desc.json: %w", err)
			}

			var uploadDesc UploadDescriptor
			if err := json.Unmarshal(data, &uploadDesc); err != nil {
				return fmt.Errorf("failed to parse desc.json: %w", err)
			}

			// Log upload information
			logger.Infof("Upload metadata: version=%s, client_version=%s, client_trait=%s, flow=%d, winlog=%d, pktlog=%d",
				uploadDesc.Version,
				uploadDesc.ClientVersion,
				uploadDesc.ClientTrait,
				len(uploadDesc.Flow),
				len(uploadDesc.WinLog),
				len(uploadDesc.PktLog))

			// Queue upload log asynchronously
			logEntry := map[string]any{
				"_log_type":      "upload",
				"timestamp":      time.Now().Format(time.RFC3339),
				"remote_ip":      remoteAddr,
				"client_version": uploadDesc.ClientVersion,
				"client_trait":   uploadDesc.ClientTrait,
				"package_file":   filepath.Base(zipPath),
				"rules_count": map[string]int{
					"flow":   len(uploadDesc.Flow),
					"winlog": len(uploadDesc.WinLog),
					"pktlog": len(uploadDesc.PktLog),
				},
			}

			select {
			case s.logQueue <- logEntry:
				// Log queued successfully
			default:
				logger.Warnf("Log queue full, dropping upload log entry")
			}

			return nil
		}
	}

	return fmt.Errorf("desc.json not found in uploaded package")
}

// generateRulePackage generates a rule package from MongoDB
func (s *Server) generateRulePackage() error {
	version := fmt.Sprintf("%d", time.Now().Unix())
	packageName := fmt.Sprintf("ada_rule_%s", version)

	// Create temporary directory
	tmpDir := filepath.Join(s.packageDir, "tmp_"+version)
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

	// Initialize descriptor
	descriptor := RuleDescriptor{
		Version: version,
		Flow:    make([]RuleMetadata, 0),
		PktLog:  make([]RuleMetadata, 0),
		WinLog:  make([]RuleMetadata, 0),
	}

	// Process flow rules from MongoDB (AlertRule)
	if err := s.processFlowRulesFromMongoDB(flowDir, &descriptor.Flow); err != nil {
		logger.Errorf("Failed to process flow rules from MongoDB: %v", err)
	}

	// Process activity rules from MongoDB (AlertActivityRule) - split by logsource
	if err := s.processActivityRulesFromMongoDB(pktlogDir, winlogDir, &descriptor.PktLog, &descriptor.WinLog); err != nil {
		logger.Errorf("Failed to process activity rules from MongoDB: %v", err)
	}

	// Generate desc.json
	descData, err := json.MarshalIndent(descriptor, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal descriptor: %w", err)
	}

	descPath := filepath.Join(tmpDir, "desc.json")
	if err := os.WriteFile(descPath, descData, 0644); err != nil {
		return fmt.Errorf("failed to write desc.json: %w", err)
	}

	// Create ZIP package
	zipPath := filepath.Join(s.packageDir, packageName+".zip")
	if err := s.createZipArchive(tmpDir, zipPath, packageName); err != nil {
		return fmt.Errorf("failed to create zip: %w", err)
	}

	// Calculate MD5 of ZIP file
	zipMD5, err := calculateFileMD5(zipPath)
	if err != nil {
		return fmt.Errorf("failed to calculate MD5: %w", err)
	}

	// Generate latest.json
	versionInfo := RuleVersionInfo{
		Version: version,
		MD5:     zipMD5,
	}

	versionData, err := json.MarshalIndent(versionInfo, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal version info: %w", err)
	}

	latestJSONPath := filepath.Join(s.packageDir, "latest.json")
	if err := os.WriteFile(latestJSONPath, versionData, 0644); err != nil {
		return fmt.Errorf("failed to write latest.json: %w", err)
	}

	// Copy/link to latest.zip
	latestZipPath := filepath.Join(s.packageDir, "latest.zip")
	os.Remove(latestZipPath) // Remove old link/file

	// Copy file
	src, err := os.Open(zipPath)
	if err != nil {
		return err
	}
	defer src.Close()

	dst, err := os.Create(latestZipPath)
	if err != nil {
		return err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return err
	}

	logger.Infof("Generated package: %s (MD5: %s)", packageName+".zip", zipMD5)
	logger.Infof("Flow rules: %d, Winlog rules: %d, Pktlog rules: %d",
		len(descriptor.Flow), len(descriptor.WinLog), len(descriptor.PktLog))

	return nil
}

// processActivityRulesFromMongoDB processes AlertActivityRule documents from MongoDB and splits them into pktlog/winlog
func (s *Server) processActivityRulesFromMongoDB(pktlogDir, winlogDir string, pktlogMeta, winlogMeta *[]RuleMetadata) error {
	var activityRules []model.AlertActivityRule

	// Query all enabled activity rules from MongoDB
	query := bson.M{}
	if err := s.mongoCli.FindAll(s.shutdownCtx, "tb_activity_rule", query, &activityRules); err != nil {
		return fmt.Errorf("failed to query activity rules: %w", err)
	}

	logger.Infof("Found %d activity rules in MongoDB", len(activityRules))

	for _, rule := range activityRules {
		// Convert rule to YAML
		ruleBytes, err := yaml.Marshal(&rule)
		if err != nil {
			logger.Errorf("Failed to marshal activity rule %s: %v", rule.ID, err)
			continue
		}

		// Generate filename from rule ID
		filename := fmt.Sprintf("%s.yml", sanitizeFilename(rule.ID))

		// Determine destination directory based on logsource
		var dstDir string
		var metaList *[]RuleMetadata

		if strings.Contains(rule.Logsource, "winlog") || strings.Contains(rule.Logsource, "windows") {
			dstDir = winlogDir
			metaList = winlogMeta
		} else {
			// Default to pktlog for other sources
			dstDir = pktlogDir
			metaList = pktlogMeta
		}

		dstPath := filepath.Join(dstDir, filename)

		// Write YAML file
		if err := os.WriteFile(dstPath, ruleBytes, 0644); err != nil {
			logger.Errorf("Failed to write activity rule file %s: %v", filename, err)
			continue
		}

		// Calculate MD5s
		fileMD5 := calculateStringMD5(string(ruleBytes))
		detectionMD5 := ""
		if len(rule.Detection) > 0 {
			detectionBytes, _ := json.Marshal(rule.Detection)
			detectionMD5 = calculateStringMD5(string(detectionBytes))
		}

		metadata := RuleMetadata{
			ID:           rule.ID,
			UpdateTm:     rule.UpdateTm.Unix(),
			Filename:     filename,
			MD5:          fileMD5,
			DetectionMD5: detectionMD5,
		}

		*metaList = append(*metaList, metadata)
	}

	logger.Infof("Processed %d activity rules (%d pktlog, %d winlog)",
		len(activityRules), len(*pktlogMeta), len(*winlogMeta))
	return nil
}

// processFlowRulesFromMongoDB processes AlertRule documents from MongoDB
func (s *Server) processFlowRulesFromMongoDB(dstDir string, metaList *[]RuleMetadata) error {
	var alertRules []model.AlertRule

	// Query all alert rules from MongoDB
	query := bson.M{}
	if err := s.mongoCli.FindAll(s.shutdownCtx, "tb_alert_rule", query, &alertRules); err != nil {
		return fmt.Errorf("failed to query alert rules: %w", err)
	}

	logger.Infof("Found %d alert rules in MongoDB", len(alertRules))

	for _, rule := range alertRules {
		// Convert rule to YAML
		ruleBytes, err := yaml.Marshal(&rule)
		if err != nil {
			logger.Errorf("Failed to marshal alert rule %s: %v", rule.ID, err)
			continue
		}

		// Generate filename from rule ID
		filename := fmt.Sprintf("%s.yml", sanitizeFilename(rule.ID))
		dstPath := filepath.Join(dstDir, filename)

		// Write YAML file
		if err := os.WriteFile(dstPath, ruleBytes, 0644); err != nil {
			logger.Errorf("Failed to write alert rule file %s: %v", filename, err)
			continue
		}

		// Calculate MD5s
		fileMD5 := calculateStringMD5(string(ruleBytes))
		detectionMD5 := ""
		// AlertDetection is a struct, always marshal it
		detectionBytes, _ := json.Marshal(rule.Detection)
		detectionMD5 = calculateStringMD5(string(detectionBytes))

		metadata := RuleMetadata{
			ID:           rule.ID,
			UpdateTm:     rule.UpdateTm.Unix(),
			Filename:     filename,
			MD5:          fileMD5,
			DetectionMD5: detectionMD5,
		}

		*metaList = append(*metaList, metadata)
	}

	logger.Infof("Processed %d flow rules to %s (successful: %d)", len(alertRules), dstDir, len(*metaList))
	return nil
}

// sanitizeFilename sanitizes a string to be used as a filename
func sanitizeFilename(s string) string {
	// Replace invalid filename characters
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
	)
	return replacer.Replace(s)
}

// createZipArchive creates a ZIP archive from a directory with a parent directory in the zip
func (s *Server) createZipArchive(srcDir, zipPath, parentDir string) error {
	zipFile, err := os.Create(zipPath)
	if err != nil {
		return err
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	return filepath.Walk(srcDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if info.IsDir() {
			if path == srcDir {
				return nil
			}
			relPath, err := filepath.Rel(srcDir, path)
			if err != nil {
				return err
			}
			dirPath := filepath.ToSlash(filepath.Join(parentDir, relPath)) + "/"
			_, err = zipWriter.Create(dirPath)
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(srcDir, path)
		if err != nil {
			return err
		}

		// Add parent directory to the zip path
		zipPath := filepath.ToSlash(filepath.Join(parentDir, relPath))

		// Create ZIP entry
		writer, err := zipWriter.Create(zipPath)
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

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
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
