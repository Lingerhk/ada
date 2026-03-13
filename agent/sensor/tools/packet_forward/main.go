//go:build tools

package main

import (
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	var forwardingActive bool
	var stopChan chan struct{}

	startForward := 1

	for {
		log.Printf("startForward: %d", startForward)

		if startForward == 1 && !forwardingActive {
			log.Printf("start forwarding.....")
			stopChan = make(chan struct{})
			go runPacketForward(stopChan)
			forwardingActive = true
		} else if startForward != 1 && forwardingActive {
			log.Printf("stop forwarding.....")
			close(stopChan)
			forwardingActive = false
		}

		time.Sleep(1 * time.Second)
	}
}

func runPacketForward(stopChan <-chan struct{}) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Println("find devices error:", err)
		return
	}

	var devName string
	for _, dev := range devs {
		if strings.Contains(strings.ToLower(dev.Name), "eth") {
			devName = dev.Name
			break
		}
	}
	if devName == "" {
		log.Println("no valid device found")
		return
	}

	handle, err := pcap.OpenLive(devName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Println("open device error:", err)
		return
	}
	defer handle.Close()

	conn, err := net.Dial("udp", "127.0.0.1:9093")
	if err != nil {
		log.Println("dial udp error:", err)
		return
	}
	defer conn.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	for {
		select {
		case <-stopChan:
			return
		case packet, ok := <-packetSource.Packets():
			if !ok {
				return
			}
			if _, err := conn.Write(packet.Data()); err != nil {
				fmt.Println("forward packet error:", err)
			}
		}
	}
}
