//go:build !windows

package plugin

import (
	"context"
	"fmt"
	"sync"
)

// pktPlugin is a stub on non-Windows platforms: packet capture relies on
// Npcap/libpcap through cgo, and the sensor only ships for Windows. The stub
// keeps the rest of the package buildable (and testable) on Linux/macOS.
type pktPlugin struct {
	mu         sync.RWMutex
	bpfFilter  string
	IfaceNames []string
	remoteAddr string
}

func NewPktPlugin(ctx context.Context, adaHost string, pktSrvPort int) (*pktPlugin, error) {
	return &pktPlugin{remoteAddr: fmt.Sprintf("%s:%d", adaHost, pktSrvPort)}, nil
}

func (p *pktPlugin) SetBpfFilter(bpfFilter string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.bpfFilter = bpfFilter
	return nil
}

func (p *pktPlugin) Start() error {
	return fmt.Errorf("packet plugin is only supported on windows")
}

func (p *pktPlugin) Stop() error {
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
	return fmt.Errorf("pkt plugin not running")
}

func (p *pktPlugin) IsRunning() bool {
	return false
}
