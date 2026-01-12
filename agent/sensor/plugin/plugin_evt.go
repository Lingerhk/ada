package plugin

import (
	"ada/agent/sensor/stats"
	"ada/agent/sensor/winevt/operator"
	"ada/agent/sensor/winevt/operator/input/windows"
	"ada/agent/sensor/winevt/operator/output/syslog"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	logger "github.com/sirupsen/logrus"
)

// defaultChannels is the base list of channels - do NOT modify directly
var defaultChannelsList = []string{
	"Application",
	"System",
	"Security",
	"Directory Service",
	"Microsoft-Windows-PowerShell/Operational",
	"Microsoft-Windows-TaskScheduler/Operational",
	"Microsoft-Windows-WMI-Activity/Operational",
	"Microsoft-Windows-SMBClient/Security",
	"Microsoft-Windows-TerminalServices-RDPClient/Operational",
	"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
	"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
}

const (
	rpcFwChannel  = "RPCFW"
	ldapFwChannel = "LDAPFW"
)

type evtPlugin struct {
	mu            sync.RWMutex // Protects inputs, EventFilter
	Channels      []string
	PollInterval  time.Duration
	SyslogAddress string
	SyslogNetwork string
	SyslogTag     string
	EventFilter   string // Event filter

	settings     operator.BaseSettings
	syslogOutput operator.Operator
	inputs       []operator.Operator
	persister    operator.Persister
}

func NewEvtPlugin(adaHost string, evtSrvPort int) (*evtPlugin, error) {
	log := logrus.New()

	// Create a local copy of the default channels to avoid mutating the global
	channels := make([]string, len(defaultChannelsList))
	copy(channels, defaultChannelsList)

	// Append optional channels based on installed plugins
	if isRpcFwInstalled() {
		channels = append(channels, rpcFwChannel)
	}
	if isLdapFwInstalled() {
		channels = append(channels, ldapFwChannel)
	}

	// TODO: 检查syslogAddress是否合法

	return &evtPlugin{
		Channels:      channels,
		PollInterval:  1 * time.Second,
		SyslogNetwork: "udp",
		SyslogAddress: fmt.Sprintf("%s:%d", adaHost, evtSrvPort),
		SyslogTag:     "ADASensor",
		settings:      operator.BaseSettings{Logger: log},
		persister:     operator.NewScopedPersister("ada", &operator.NoopPersister{}),
		inputs:        make([]operator.Operator, 0),
	}, nil
}

func (e *evtPlugin) createChannelInput(channel string) (operator.Operator, error) {
	windowsConfig := windows.NewConfig()
	windowsConfig.Channel = channel
	windowsConfig.StartAt = "end"
	windowsConfig.PollInterval = e.PollInterval
	windowsConfig.OutputIDs = []string{"syslog"}
	windowsConfig.EventFilter = e.EventFilter

	input, err := windowsConfig.Build(e.settings)
	if err != nil {
		return nil, fmt.Errorf("failed to build windows event log input: %v", err)
	}

	err = input.SetOutputs([]operator.Operator{e.syslogOutput})
	if err != nil {
		return nil, fmt.Errorf("failed to connect operators: %v", err)
	}

	if err := input.Start(e.persister); err != nil {
		// TODO: 处理channel不存在的情况
		return nil, fmt.Errorf("failed to start windows event log input: %v", err)
	}

	return input, nil
}

func (e *evtPlugin) Start() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Create syslog output configuration
	syslogConfig := syslog.NewConfig("syslog")
	syslogConfig.Network = e.SyslogNetwork
	syslogConfig.Address = e.SyslogAddress
	syslogConfig.Tag = e.SyslogTag
	syslogConfig.Hostname = stats.GetFQDNName()

	var err error
	e.syslogOutput, err = syslogConfig.Build(e.settings)
	if err != nil {
		return fmt.Errorf("failed to build syslog output: %v", err)
	}

	if err := e.syslogOutput.Start(e.persister); err != nil {
		return fmt.Errorf("failed to start syslog output: %v", err)
	}

	// Create an input for each channel
	for _, channel := range e.Channels {
		input, err := e.createChannelInput(channel)
		if err != nil {
			if strings.Contains(err.Error(), "The specified channel could not be found.") {
				logger.Warnf("ignore to create input channel %s as it does not exist!", channel)
				continue
			}
			e.stopInternal() // Clean up any started inputs (without lock)
			return fmt.Errorf("failed to create input for channel %s: %v, will stop all channels", channel, err)
		}

		e.inputs = append(e.inputs, input)
	}

	logger.Infof("evt plugin started with %d channels", len(e.inputs))

	return nil
}

// stopInternal stops the plugin without acquiring the lock (caller must hold lock)
func (e *evtPlugin) stopInternal() error {
	var errs []error

	// Stop all inputs
	for _, input := range e.inputs {
		if err := input.Stop(); err != nil {
			errs = append(errs, err)
		}
	}

	// Clear inputs array
	e.inputs = make([]operator.Operator, 0)

	// Stop the output
	if e.syslogOutput != nil {
		if err := e.syslogOutput.Stop(); err != nil {
			errs = append(errs, err)
		}
		e.syslogOutput = nil
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors stopping pipeline: %v", errs)
	}

	return nil
}

func (e *evtPlugin) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.stopInternal()
}

func (e *evtPlugin) Set(channels []string, syslogNetwork, syslogAddress string, pollInterval time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.Channels = channels
	e.SyslogNetwork = syslogNetwork
	e.SyslogAddress = syslogAddress
	e.PollInterval = pollInterval
}

func (e *evtPlugin) GetEventFilter() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.EventFilter
}

func (e *evtPlugin) SetEventFilter(filter string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.EventFilter = filter
}

func (e *evtPlugin) Reload() error {
	if !e.IsRunning() {
		return fmt.Errorf("evt plugin not running")
	}

	if err := e.Stop(); err != nil {
		return err
	}

	return e.Start()
}

func (e *evtPlugin) IsRunning() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.inputs) > 0
}
