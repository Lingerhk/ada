package main

// GOOS=linux GOARCH=amd64 go build syslog_svc.go

import (
	"fmt"
	"gopkg.in/mcuadros/go-syslog.v2"
	"time"
)

func main() {
	channel := make(syslog.LogPartsChannel)
	handler := syslog.NewChannelHandler(channel)

	server := syslog.NewServer()
	server.SetFormat(syslog.RFC5424)
	server.SetHandler(handler)
	err := server.ListenUDP("0.0.0.0:514")
	if err != nil {
		panic(err)
	}

	err = server.Boot()
	if err != nil {
		panic(err)
	}

	fmt.Println("start syslog server 0.0.0.0:514/udp")

	go func(channel syslog.LogPartsChannel) {
		for logParts := range channel {
			fmt.Printf("[%s] recv syslog:%#v\n", time.Now().Format("2006-01-02 15:04:05"), logParts)
		}
	}(channel)

	server.Wait()
}
