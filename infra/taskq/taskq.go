// Package taskq is the single task-queue abstraction shared by the tasker
// (server and worker) and the scanner. All asynchronous work goes through
// machinery with a Redis broker/backend; there is no second task framework.
package taskq

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/RichardKnop/machinery/v2"
	redisbackend "github.com/RichardKnop/machinery/v2/backends/redis"
	redisbroker "github.com/RichardKnop/machinery/v2/brokers/redis"
	mconfig "github.com/RichardKnop/machinery/v2/config"
	eagerlock "github.com/RichardKnop/machinery/v2/locks/eager"
	"github.com/RichardKnop/machinery/v2/tasks"
	"github.com/redis/go-redis/v9"
)

// Queue names. Each consumer only listens on its own queue; producers address
// a queue through Signature.RoutingKey.
const (
	TaskerQueue  = "ada:tasker:task_queue"
	ScannerQueue = "ada:scanner:task_queue"
)

// Scanner task names registered by the scanner worker.
const (
	ScannerBaselineTask = "scanner.baseline"
	ScannerLeakTask     = "scanner.leak"
	ScannerWeakPwdTask  = "scanner.weakpwd"
)

// ScannerTaskName maps a scan type (baseline|leak|weakpwd) to its task name.
func ScannerTaskName(scanType string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(scanType)) {
	case "baseline":
		return ScannerBaselineTask, nil
	case "leak":
		return ScannerLeakTask, nil
	case "weakpwd":
		return ScannerWeakPwdTask, nil
	default:
		return "", fmt.Errorf("unknown scan type %q", scanType)
	}
}

// NewServer builds a machinery server using redisURI (redis://[user:]pass@host:port/db)
// for both broker and result backend. defaultQueue is the queue a worker
// created from this server consumes.
func NewServer(redisURI, defaultQueue string) (*machinery.Server, error) {
	opt, err := redis.ParseURL(redisURI)
	if err != nil {
		return nil, fmt.Errorf("parse redis uri: %w", err)
	}

	cnf := &mconfig.Config{
		DefaultQueue:    defaultQueue,
		ResultsExpireIn: 12 * 3600,
		NoUnixSignals:   true,
		Redis: &mconfig.RedisConfig{
			MaxIdle:                3,
			IdleTimeout:            240,
			ReadTimeout:            15,
			WriteTimeout:           15,
			ConnectTimeout:         15,
			NormalTasksPollPeriod:  1000,
			DelayedTasksPollPeriod: 500,
		},
	}
	if opt.TLSConfig != nil {
		cnf.TLSConfig = opt.TLSConfig
	}

	// machinery's go-redis adapters take "[user:]password@host:port".
	addr := opt.Addr
	if opt.Password != "" {
		if opt.Username != "" {
			addr = opt.Username + ":" + opt.Password + "@" + addr
		} else {
			addr = opt.Password + "@" + addr
		}
	}

	broker := redisbroker.NewGR(cnf, []string{addr}, opt.DB)
	backend := redisbackend.NewGR(cnf, []string{addr}, opt.DB)
	return machinery.NewServer(cnf, broker, backend, eagerlock.New()), nil
}

// ScannerPayload is the single argument of every scanner task. TaskID is the
// scan sub-task id the scanner reports progress against; Kwargs carries the
// scan parameters (group_id, domain, template_id, plugin_id, ...).
type ScannerPayload struct {
	TaskID string         `json:"task_id"`
	Kwargs map[string]any `json:"kwargs"`
}

// NewScannerSignature builds the machinery signature that dispatches a scan
// of scanType to the scanner queue.
func NewScannerSignature(scanType, taskID string, kwargs map[string]any) (*tasks.Signature, error) {
	name, err := ScannerTaskName(scanType)
	if err != nil {
		return nil, err
	}
	raw, err := json.Marshal(ScannerPayload{TaskID: taskID, Kwargs: kwargs})
	if err != nil {
		return nil, fmt.Errorf("encode scanner payload: %w", err)
	}
	return &tasks.Signature{
		Name:       name,
		RoutingKey: ScannerQueue,
		Args:       []tasks.Arg{{Type: "string", Value: string(raw)}},
	}, nil
}

// DecodeScannerPayload parses the argument produced by NewScannerSignature.
func DecodeScannerPayload(raw string) (ScannerPayload, error) {
	var p ScannerPayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return p, fmt.Errorf("decode scanner payload: %w", err)
	}
	if p.Kwargs == nil {
		p.Kwargs = map[string]any{}
	}
	return p, nil
}
