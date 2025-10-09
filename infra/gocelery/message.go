package gocelery

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// CeleryMessage is actual message to be sent to Redis
type CeleryMessage struct {
	Body            string                 `json:"body"`
	Headers         map[string]any `json:"headers,omitempty"`
	ContentType     string                 `json:"content-type"`
	Properties      CeleryProperties       `json:"properties"`
	ContentEncoding string                 `json:"content-encoding"`
}

func (cm *CeleryMessage) reset() {
	cm.Headers = nil
	cm.Body = ""
	cm.Properties.CorrelationID = uuid.NewString()
	cm.Properties.ReplyTo = uuid.NewString()
	cm.Properties.DeliveryTag = uuid.NewString()
	cm.Properties.DeliveryInfo.RoutingKey = ""
	cm.Properties.DeliveryInfo.Exchange = ""
}

func (cm *CeleryMessage) setHeader(taskName, taskId string, kwargs map[string]any) {
	header := make(map[string]any)
	header["lang"] = "golang"
	header["task"] = taskName
	header["id"] = taskId
	header["shadow"] = nil
	header["eta"] = nil
	header["expires"] = nil
	header["group"] = nil
	header["group_index"] = nil
	header["retries"] = 0
	header["timelimit"] = []string{}
	header["root_id"] = taskId
	header["parent_id"] = nil
	header["argsrepr"] = "()"
	header["kwargsrepr"] = kwargs
	header["origin"] = "localhost@ada"
	header["ignore_result"] = false
	cm.Headers = header
}

func (cm *CeleryMessage) setDeliveryInfo(taskName string) {
	taskMap := map[string]string{
		"tasks.leak.execute_leak":         "leak_task",
		"tasks.baseline.execute_baseline": "baseline_task",
		"tasks.weakpwd.execute_weakpwd":   "weakpwd_task",
	}

	taskRouter, ok := taskMap[taskName]
	if !ok {
		return
	}

	cm.Properties.DeliveryInfo.RoutingKey = taskRouter
	cm.Properties.DeliveryInfo.Exchange = taskRouter
}

var celeryMessagePool = sync.Pool{
	New: func() any {
		return &CeleryMessage{
			Body:        "",
			Headers:     nil,
			ContentType: "application/json",
			Properties: CeleryProperties{
				Priority:      0,
				BodyEncoding:  "base64",
				CorrelationID: uuid.NewString(),
				ReplyTo:       uuid.NewString(),
				DeliveryInfo: CeleryDeliveryInfo{
					Priority:   0,
					RoutingKey: "celery",
					Exchange:   "celery",
				},
				DeliveryMode: 2,
				DeliveryTag:  uuid.NewString(),
			},
			ContentEncoding: "utf-8",
		}
	},
}

func getCeleryMessage(encodedTaskMessage string) *CeleryMessage {
	msg := celeryMessagePool.Get().(*CeleryMessage)
	msg.Body = encodedTaskMessage

	return msg
}

func releaseCeleryMessage(v *CeleryMessage) {
	v.reset()
	celeryMessagePool.Put(v)
}

// CeleryProperties represents properties json
type CeleryProperties struct {
	Priority      int                `json:"priority"`
	BodyEncoding  string             `json:"body_encoding"`
	CorrelationID string             `json:"correlation_id"`
	ReplyTo       string             `json:"reply_to"`
	DeliveryInfo  CeleryDeliveryInfo `json:"delivery_info"`
	DeliveryMode  int                `json:"delivery_mode"`
	DeliveryTag   string             `json:"delivery_tag"`
}

// CeleryDeliveryInfo represents deliveryinfo json
type CeleryDeliveryInfo struct {
	Priority   int    `json:"priority"`
	RoutingKey string `json:"routing_key"`
	Exchange   string `json:"exchange"`
}

// GetTaskMessage retrieve and decode task messages from broker
func (cm *CeleryMessage) GetTaskMessage() *TaskMessage {
	// ensure content-type is 'application/json'
	if cm.ContentType != "application/json" {
		log.Println("unsupported content type " + cm.ContentType)
		return nil
	}
	// ensure body encoding is base64
	if cm.Properties.BodyEncoding != "base64" {
		log.Println("unsupported body encoding " + cm.Properties.BodyEncoding)
		return nil
	}
	// ensure content encoding is utf-8
	if cm.ContentEncoding != "utf-8" {
		log.Println("unsupported encoding " + cm.ContentEncoding)
		return nil
	}
	// decode body
	taskMessage, err := DecodeTaskMessage(cm.Body)
	if err != nil {
		log.Println("failed to decode task message")
		return nil
	}
	return taskMessage
}

// TaskMessage is celery-compatible message
type TaskMessage struct {
	TaskID  string                 `json:"task_id"`
	Task    string                 `json:"task"`
	Args    []any          `json:"args"`
	Kwargs  map[string]any `json:"kwargs"`
	Retries int                    `json:"retries"`
	ETA     *string                `json:"eta"`
	Expires *time.Time             `json:"expires"`
}

func (tm *TaskMessage) reset() {
	tm.TaskID = strings.ReplaceAll(uuid.NewString(), "-", "")
	tm.Task = ""
	tm.Args = nil
	tm.Kwargs = nil
}

var taskMessagePool = sync.Pool{
	New: func() any {
		eta := time.Now().Format(time.RFC3339)
		return &TaskMessage{
			TaskID:  strings.ReplaceAll(uuid.NewString(), "-", ""),
			Retries: 0,
			Kwargs:  nil,
			ETA:     &eta,
		}
	},
}

func getTaskMessage(task string) *TaskMessage {
	msg := taskMessagePool.Get().(*TaskMessage)
	msg.Task = task
	msg.Args = make([]any, 0)
	msg.Kwargs = make(map[string]any)
	msg.ETA = nil
	return msg
}

func releaseTaskMessage(v *TaskMessage) {
	v.reset()
	taskMessagePool.Put(v)
}

// DecodeTaskMessage decodes base64 encrypted body and return TaskMessage object
func DecodeTaskMessage(encodedBody string) (*TaskMessage, error) {
	body, err := base64.StdEncoding.DecodeString(encodedBody)
	if err != nil {
		return nil, err
	}
	message := taskMessagePool.Get().(*TaskMessage)
	err = json.Unmarshal(body, message)
	if err != nil {
		return nil, err
	}
	return message, nil
}

// Encode returns base64 json encoded string
func (tm *TaskMessage) Encode() (string, error) {
	if tm.Args == nil {
		tm.Args = make([]any, 0)
	}
	jsonData, err := json.Marshal(tm)
	if err != nil {
		return "", err
	}
	encodedData := base64.StdEncoding.EncodeToString(jsonData)
	return encodedData, err
}

// ResultMessage is return message received from broker
type ResultMessage struct {
	ID        string        `json:"task_id"`
	Status    string        `json:"status"`
	Traceback any   `json:"traceback"`
	Result    any   `json:"result"`
	Children  []any `json:"children"`
}

func (rm *ResultMessage) reset() {
	rm.Result = nil
}

var resultMessagePool = sync.Pool{
	New: func() any {
		return &ResultMessage{
			Status:    "SUCCESS",
			Traceback: nil,
			Children:  nil,
		}
	},
}

func getResultMessage(val any) *ResultMessage {
	msg := resultMessagePool.Get().(*ResultMessage)
	msg.Result = val
	return msg
}

func getReflectionResultMessage(val *reflect.Value) *ResultMessage {
	msg := resultMessagePool.Get().(*ResultMessage)
	msg.Result = GetRealValue(val)
	return msg
}

func releaseResultMessage(v *ResultMessage) {
	v.reset()
	resultMessagePool.Put(v)
}

// GetRealValue returns real value of reflect.Value
// Required for JSON Marshalling
func GetRealValue(val *reflect.Value) any {
	if val == nil {
		return nil
	}
	switch val.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return val.Int()
	case reflect.String:
		return val.String()
	case reflect.Bool:
		return val.Bool()
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return val.Uint()
	case reflect.Float32, reflect.Float64:
		return val.Float()
	case reflect.Slice, reflect.Map:
		return val.Interface()
	default:
		return nil
	}
}
