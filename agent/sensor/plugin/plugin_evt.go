package plugin

import (
	"ada/agent/sensor/winevt/operator"
	"ada/agent/sensor/winevt/operator/input/windows"
	"ada/agent/sensor/winevt/operator/output/syslog"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	logger "github.com/sirupsen/logrus"
)

var (
	defaultChannels = []string{"Application", "System", "Security", "Directory Service", "Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-TaskScheduler/Operational", "Microsoft-Windows-WMI-Activity/Operational", "Microsoft-Windows-SMBClient/Security", "Microsoft-Windows-TerminalServices-RDPClient/Operational", "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational"}
	rpcFwChannel    = "RPCFW"
	ldapFwChannel   = "LDAPFW"
)

type evtPlugin struct {
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
	logger := logrus.New()

	if isRpcFwInstalled() {
		defaultChannels = append(defaultChannels, rpcFwChannel)
	}
	if isLdapFwInstalled() {
		defaultChannels = append(defaultChannels, ldapFwChannel)
	}

	// TODO: 检查syslogAddress是否合法

	return &evtPlugin{
		Channels:      defaultChannels,
		PollInterval:  1 * time.Second,
		SyslogNetwork: "udp",
		SyslogAddress: fmt.Sprintf("%s:%d", adaHost, evtSrvPort),
		SyslogTag:     "ADASensor",
		settings:      operator.BaseSettings{Logger: logger},
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
	// Create syslog output configuration
	syslogConfig := syslog.NewConfig("syslog")
	syslogConfig.Network = e.SyslogNetwork
	syslogConfig.Address = e.SyslogAddress
	syslogConfig.Tag = e.SyslogTag
	syslogConfig.Hostname = getFQDNName()

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
			e.Stop() // Clean up any started inputs
			return fmt.Errorf("failed to create input for channel %s: %v, will stop all channels", channel, err)
		}

		e.inputs = append(e.inputs, input)
	}

	logger.Infof("evt plugin started with %d channels", len(e.inputs))

	return nil
}

func (e *evtPlugin) Stop() error {
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

func (e *evtPlugin) Set(channels []string, syslogNetwork, syslogAddress string, pollInterval time.Duration) {
	e.Channels = channels
	e.SyslogNetwork = syslogNetwork
	e.SyslogAddress = syslogAddress
	e.PollInterval = pollInterval
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
	return len(e.inputs) > 0
}
