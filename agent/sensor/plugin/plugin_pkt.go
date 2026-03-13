package plugin

import (
	"ada/agent/sensor/common"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	logger "github.com/sirupsen/logrus"
)

const (
	snapshotLen int32 = 1500
)

type pktPlugin struct {
	parentCtx  context.Context // Parent context for cancellation chain
	ctx        context.Context
	bpfFilter  string
	IfaceNames []string
	remoteHost string
	remoteAddr string

	mu      sync.RWMutex // Protects handles, IfaceNames, bpfFilter
	handles map[string]*pcap.Handle
	wg      sync.WaitGroup
	cancel  context.CancelFunc
	sock    *net.UDPConn // UDP socket for sending packets (connected via DialUDP)
}

func NewPktPlugin(ctx context.Context, adaHost string, pktSrvPort int) (*pktPlugin, error) {
	bpfFilter := fmt.Sprintf(common.DefaultBpfFilter, adaHost) // TODO: adaHost为域名的话，需要解析为ip

	return &pktPlugin{
		parentCtx:  ctx, // Store parent context for cancellation chain
		remoteHost: adaHost,
		remoteAddr: fmt.Sprintf("%s:%d", adaHost, pktSrvPort),
		bpfFilter:  bpfFilter,
		handles:    make(map[string]*pcap.Handle),
	}, nil
}

func (p *pktPlugin) createConn() error {
	var err error
	udpAddr, err := net.ResolveUDPAddr("udp", p.remoteAddr)
	if err != nil {
			logger.Errorf("failed to resolve remote UDP address '%s': %v", p.remoteAddr, err)
		return err
	}

	p.sock, err = net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		logger.Errorf("failed to dial UDP socket to %s: %v", p.remoteAddr, err)
		return err
	}

	logger.Debugf("UDP socket connected to remote target: %s", p.sock.RemoteAddr().String())

	return nil
}

func (p *pktPlugin) getInterfaces(ifaceName string) (string, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil || len(devs) == 0 {
		return "", fmt.Errorf("get interfaces error or no interfaces: %v", err)
	}

	for _, dev := range devs {
		if dev.Name == ifaceName {
			return dev.Name, nil
		}
	}

	return "", fmt.Errorf("ifaceName(%s) not found", ifaceName)
}

func (p *pktPlugin) SetBpfFilter(bpfFilter string) error {
	var newBpfFilter string

	if strings.Contains(bpfFilter, "%s") {
		newBpfFilter = fmt.Sprintf(bpfFilter, p.remoteHost)
	} else {
		newBpfFilter = fmt.Sprintf("%s and (not (host %s))", bpfFilter, p.remoteHost)
	}

	if !p.IsRunning() {
		// Store the filter for later use when plugin starts
		p.mu.Lock()
		p.bpfFilter = newBpfFilter
		p.mu.Unlock()
		logger.Infof("pkt plugin not running, stored bpf filter for later use")
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if newBpfFilter == p.bpfFilter {
		logger.Debugf("bpf filter not changed, skip setting")
		return nil
	}

	for iface, handle := range p.handles {
		err := handle.SetBPFFilter(newBpfFilter)
		if err != nil {
			logger.Errorf("setting BPF filter '%s' on device %s err:%v", p.bpfFilter, iface, err)
			continue
		}
	}

	p.bpfFilter = newBpfFilter
	logger.Infof("set bpf filter(%s) success", p.bpfFilter)

	return nil
}

func (p *pktPlugin) capturePackets(handle *pcap.Handle, iface string) {
	defer p.wg.Done()
	defer handle.Close() // Ensure handle is closed when goroutine exits

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetChan := packetSource.Packets()

	logger.Infof("packet plugin: listening on interface %s", iface)

	for {
		select {
		case <-p.ctx.Done():
			logger.Infof("packet plugin stopping capture on interface %s due to context cancellation.", iface)
			return
		case packet, ok := <-packetChan:
			if !ok {
				logger.Infof("packet plugin: packet channel closed for interface %s.", iface)
				return
			}
			// Process the packet here
			if p.sock != nil {
				packetData := packet.Data()
				_, err := p.sock.Write(packetData)
				if err != nil {
					logger.Errorf("Error sending packet from %s over UDP to %s: %v", iface, p.sock.RemoteAddr().String(), err)
				}
			} else {
				logger.Errorf("UDP socket not initialized, cannot send packet from %s.", iface)
			}
		}
	}
}

func (p *pktPlugin) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Use parent context for proper cancellation chain
	p.ctx, p.cancel = context.WithCancel(p.parentCtx)

	if len(p.IfaceNames) == 0 {
		return fmt.Errorf("no interfaces specified")
	}

	if len(p.handles) > 0 {
		return fmt.Errorf("packet collector already running")
	}

	err := p.createConn()
	if err != nil {
		logger.Errorf("failed to create UDP socket: %v", err)
		return err
	}

	// Make a copy of IfaceNames to iterate safely
	ifaceNames := make([]string, len(p.IfaceNames))
	copy(ifaceNames, p.IfaceNames)
	bpfFilter := p.bpfFilter

	for _, ifaceName := range ifaceNames {
		iface, err := p.getInterfaces(ifaceName)
		if err != nil {
			logger.Errorf("Error getting interface %s: %v", ifaceName, err)
			continue
		}

		handle, err := pcap.OpenLive(iface, snapshotLen, false, pcap.BlockForever)
		if err != nil {
			logger.Errorf("Error opening device %s: %v", iface, err)
			// Consider how to handle errors - stop all? continue with others?
			// For now, log and skip this interface.
			continue
		}

		if bpfFilter != "" {
			err = handle.SetBPFFilter(bpfFilter)
			if err != nil {
				logger.Errorf("Error setting BPF filter '%s' on device %s: %v", bpfFilter, iface, err)
				handle.Close()
				continue
			}
		}

		p.handles[iface] = handle
		p.wg.Add(1)
		go p.capturePackets(handle, iface)
		logger.Infof("Started capture goroutine for interface: %s", iface)
	}

	if len(p.handles) == 0 {
		logger.Error("Failed to start capture on any interface.")
		if p.cancel != nil {
			p.cancel()
			p.cancel = nil
		}
		if p.sock != nil {
			p.sock.Close()
			p.sock = nil
		}
		return fmt.Errorf("failed to open any specified interfaces")
	}

	return nil
}

func (p *pktPlugin) Stop() error {
	p.mu.Lock()
	cancel := p.cancel
	p.mu.Unlock()

	if cancel != nil {
		logger.Info("packet plugin: stopping packet capture goroutines...")
		cancel()
	} else {
		// If not running (no cancel func), still ensure socket is closed if it exists
		p.mu.Lock()
		if p.sock != nil {
			logger.Info("packet plugin: collector not running, ensuring UDP socket is closed.")
			p.sock.Close()
			p.sock = nil
		}
		p.mu.Unlock()

		logger.Info("packet plugin: packet collector not running.")
		return nil
	}

	p.wg.Wait() // Wait for all capture goroutines to finish

	p.mu.Lock()
	defer p.mu.Unlock()

	logger.Info("packet plugin: all packet capture goroutines stopped.")
	p.handles = make(map[string]*pcap.Handle) // Clear handles
	p.cancel = nil                            // Reset cancel func

	// Close the UDP socket when stopping
	if p.sock != nil {
		logger.Info("packet plugin: closing UDP socket.")
		p.sock.Close()
		p.sock = nil
	}

	return nil
}

func (p *pktPlugin) Set(remoteAddr, bpfFilter string, ifaceNames []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.remoteAddr = remoteAddr
	p.bpfFilter = bpfFilter
	p.IfaceNames = ifaceNames
}

func (p *pktPlugin) SetIfaceNames(ifaceNames []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.IfaceNames = ifaceNames
}

func (p *pktPlugin) GetIfaceNames() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	result := make([]string, len(p.IfaceNames))
	copy(result, p.IfaceNames)
	return result
}

func (p *pktPlugin) Reload() error {
	if !p.IsRunning() {
		return fmt.Errorf("pkt plugin not running")
	}

	if err := p.Stop(); err != nil {
		return err
	}

	return p.Start()
}

func (p *pktPlugin) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.handles) > 0
}
