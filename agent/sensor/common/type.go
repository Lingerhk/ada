package common

type AdaMessage struct {
	Code      int               `json:"code"`
	TaskID    string            `json:"task_id"`
	AgentID   string            `json:"agent_id"`
	MsgType   int32             `json:"msg_type"`
	Version   string            `json:"version"`
	Timestamp int64             `json:"timestamp"`
	Data      map[string]string `json:"data"`
}
