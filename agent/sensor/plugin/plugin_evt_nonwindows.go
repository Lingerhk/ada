//go:build !windows

package plugin

import (
	"fmt"
	"time"
)

type evtPlugin struct {
	Channels      []string
	PollInterval  time.Duration
	SyslogAddress string
	SyslogNetwork string
	SyslogTag     string
	EventFilter   string
}

func NewEvtPlugin(adaHost string, evtSrvPort int) (*evtPlugin, error) {
	return &evtPlugin{
		PollInterval: 1 * time.Second,
	}, nil
}

func (e *evtPlugin) Start() error {
	return fmt.Errorf("event log plugin is only supported on windows")
}

func (e *evtPlugin) Stop() error {
	return nil
}

func (e *evtPlugin) Set(channels []string, syslogNetwork, syslogAddress string, pollInterval time.Duration) {
	e.Channels = channels
	e.SyslogNetwork = syslogNetwork
	e.SyslogAddress = syslogAddress
	e.PollInterval = pollInterval
}

func (e *evtPlugin) GetEventFilter() string {
	return e.EventFilter
}

func (e *evtPlugin) SetEventFilter(filter string) {
	e.EventFilter = filter
}

func (e *evtPlugin) Reload() error {
	return fmt.Errorf("event log plugin is only supported on windows")
}

func (e *evtPlugin) IsRunning() bool {
	return false
}
