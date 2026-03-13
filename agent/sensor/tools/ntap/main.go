//go:build tools

package main

import (
	"fmt"
	"log"
	"net"
	"os/exec"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/songgao/water"
)

const (
	udpLocalPort     = 9093
	tapInterfaceName = "tap0"
	maxUDPPacketSize = 1534
)

func main() {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", udpLocalPort))
	if err != nil {
		log.Fatal("Error resolving UDP address:", err)
	}

	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal("Error listening on UDP port:", err)
	}
	defer udpConn.Close()

	config := water.Config{
		DeviceType: water.TAP,
	}
	config.Name = tapInterfaceName

	ifce, err := water.New(config)
	if err != nil {
		log.Fatal("Error creating TAP interface:", err)
	}
	defer ifce.Close()

	cmd := exec.Command("ip", "link", "set", "dev", tapInterfaceName, "up")
	if err := cmd.Run(); err != nil {
		log.Println("Warning: failed to bring TAP interface up:", err)
	}

	buffer := make([]byte, maxUDPPacketSize)
	for {
		n, _, err := udpConn.ReadFromUDP(buffer)
		if err != nil {
			log.Println("Error reading UDP packet:", err)
			continue
		}

		packet := gopacket.NewPacket(buffer[:n], layers.LayerTypeEthernet, gopacket.Default)
		if app := packet.ApplicationLayer(); app != nil {
			if _, err := ifce.Write(app.Payload()); err != nil {
				log.Println("Error writing to TAP interface:", err)
			}
		}
	}
}
