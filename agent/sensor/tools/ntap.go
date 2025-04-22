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

// port define:
// TLS TCP 9091(redis)
// SYSLOG UDP 9092
// PKGLOG UDP 9093

// ntap_remote.exe /c -K -i 0  -c 192.168.145.133:9093 -f "(port 88 or port 389 or port 445 or port 3389) and (not (host 192.168.145.133 and port 7890)"

// ntap_remote filter:
// (tcp and port 443) and (not (host 192.168.1.1 and port 1234))

// sudo ip addr add 127.0.0.1 dev tap0
//sudo ip link set dev tap0 up

const (
	udpLocalPort     = 9093
	tapInterfaceName = "tap0"
	maxUDPPacketSize = 1534 // Make sure is 1500+34bytes
)

func main() {
	// Create a UDP listener
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("0.0.0.0:%d", udpLocalPort))
	if err != nil {
		log.Fatal("Error resolving UDP address:", err)
	}

	udpConn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatal("Error creating UDP listener:", err)
	}
	defer udpConn.Close()

	// Create a TAP interface
	config := water.Config{
		DeviceType: water.TAP,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name: tapInterfaceName,
		},
	}
	tap, err := water.New(config)
	if err != nil {
		log.Fatal("Error creating TAP interface:", err)
	}
	defer tap.Close()

	// update ip and up tap device
	tapAdd := exec.Command("/sbin/ip", "addr", "add", "127.0.0.1", "dev", tapInterfaceName)
	_, err = tapAdd.CombinedOutput()
	if err != nil {
		log.Fatal("Error updating TAP address:", err)
	}
	//
	tapUp := exec.Command("/sbin/ip", "link", "set", "dev", tapInterfaceName, "up")
	_, err = tapUp.CombinedOutput()
	if err != nil {
		log.Fatal("Error Up TAP device:", err)
	}

	log.Printf("Listening on port %d/udp and forwarding to TAP: %s\n", udpLocalPort, tapInterfaceName)

	buffer := make([]byte, maxUDPPacketSize)

	for {
		n, _, err := udpConn.ReadFrom(buffer)
		if err != nil {
			log.Println("Error reading UDP packet:", err)
			continue
		}

		// Parse Ethernet frame using gopacket
		packet := gopacket.NewPacket(buffer[20:n], layers.LayerTypeEthernet, gopacket.Default)

		// Forward the packet to the TAP interface
		n, err = tap.Write(packet.Data())
		if err != nil {
			log.Println("Error writing to TAP interface:", err)
			continue
		}
		log.Printf("Forwarded %d bytes to tap0\n", n)
	}
}
