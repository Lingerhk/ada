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

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	var bindDevice string
	for i, device := range devices {
		fmt.Printf("%d. %s (%s)\n", i+1, device.Name, device.Description)
		if strings.Contains(device.Description, "82574L") {
			bindDevice = device.Name
			break
		}
	}

	log.Printf("bindDevice: %s", bindDevice)

	handle, err := pcap.OpenLive(bindDevice, 65535, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	filter := fmt.Sprintf("port %d", 9093)
	if err := handle.SetBPFFilter(filter); err != nil {
		log.Fatal(err)
	}

	// Create a UDP connection to the destination host
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", "192.168.6.128", 9093))
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	log.Printf("start lopp forward.....")

	// Modify the packet processing loop
	go func() {
		for packet := range packetSource.Packets() {
			select {
			case <-stopChan:
				return
			default:
				// Forward the packet to the destination host
				_, err := conn.Write(packet.Data())
				if err != nil {
					log.Printf("Error forwarding packet: %v", err)
				}
			}
		}
	}()

	<-stopChan
	handle.Close()
	conn.Close()
}

// ... rest of the existing code ...
