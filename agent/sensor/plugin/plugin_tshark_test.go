package plugin

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestNormalizeTsharkField(t *testing.T) {
	tests := map[string]string{
		"ip.src":                 "SrcIp",
		"udp.dstport":            "DstPort",
		"dcerpc.cn_bind_to_uuid": "RpcInterfaceUuid",
		"_ws.col.protocol":       "Protocol",
		"custom.field-name":      "custom_field_name",
	}

	for in, want := range tests {
		if got := normalizeTsharkField(in); got != want {
			t.Fatalf("normalizeTsharkField(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEventTypeFromTsharkEvent(t *testing.T) {
	tests := []struct {
		name  string
		event map[string]any
		want  string
	}{
		{
			name:  "dcerpc uuid",
			event: map[string]any{"RpcInterfaceUuid": "1234"},
			want:  "dcerpc",
		},
		{
			name:  "epm protocol",
			event: map[string]any{"Protocol": "EPM"},
			want:  "dcerpc",
		},
		{
			name:  "dns port",
			event: map[string]any{"Protocol": "UDP", "DstPort": "53"},
			want:  "dns",
		},
		{
			name:  "smb2 protocol stack",
			event: map[string]any{"FrameProtocols": "eth:ip:tcp:netbios:ssn:smb2"},
			want:  "smb2",
		},
		{
			name:  "plain tcp",
			event: map[string]any{"Protocol": "TCP"},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := eventTypeFromTsharkEvent(tt.event); got != tt.want {
				t.Fatalf("eventTypeFromTsharkEvent() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeTsharkTimestamp(t *testing.T) {
	fallback := time.Date(2026, 4, 25, 7, 31, 39, 0, time.UTC)

	got := normalizeTsharkTimestamp("1777102299.5", fallback)
	if got != time.Unix(1777102299, 500000000).UnixMilli() {
		t.Fatalf("normalizeTsharkTimestamp() = %d", got)
	}

	got = normalizeTsharkTimestamp("", fallback)
	if got != fallback.UnixMilli() {
		t.Fatalf("fallback normalizeTsharkTimestamp() = %d", got)
	}
}

func TestEventFromTsharkFieldsLineUsesPacketTimestamp(t *testing.T) {
	now := time.Date(2026, 4, 25, 8, 30, 0, 0, time.UTC)
	p := &tsharkPlugin{
		hostname: "DC01.example.local",
		fields: []string{
			"frame.time_epoch",
			"frame.protocols",
			"ip.src",
			"ip.dst",
			"tcp.srcport",
			"tcp.dstport",
			"_ws.col.protocol",
		},
	}
	line := "2026-04-25T08:30:00.250000000Z\teth:ethertype:ip:tcp:ldap\t192.168.7.2\t192.168.1.10\t55321\t389\tTCP"

	event, err := p.eventFromTsharkFieldsLine("Ethernet 2", line, now)
	if err != nil {
		t.Fatalf("eventFromTsharkFieldsLine() err = %v", err)
	}
	if event["EventType"] != "ldap" {
		t.Fatalf("EventType = %v, want ldap", event["EventType"])
	}
	if event["@timestamp"] != time.Date(2026, 4, 25, 8, 30, 0, 250000000, time.UTC).UnixMilli() {
		t.Fatalf("@timestamp = %v", event["@timestamp"])
	}
	if _, ok := event["ts"]; ok {
		t.Fatalf("unexpected ts field: %#v", event)
	}
	if _, ok := event["FrameProtocols"]; ok {
		t.Fatalf("unexpected FrameProtocols field: %#v", event)
	}
}

func TestEventFromTsharkEKLineBuildsProtocolFields(t *testing.T) {
	now := time.Date(2026, 4, 25, 8, 30, 0, 0, time.UTC)
	p := &tsharkPlugin{hostname: "DC01.example.local"}
	line := `{"timestamp":"2026-04-25T08:30:00.000000000Z","layers":{"frame":{"frame_frame_time_epoch":"2026-04-25T08:30:00.250000000Z","frame_frame_protocols":"eth:ethertype:ip:tcp:ldap"},"ip":{"ip_ip_src":"192.168.7.2","ip_ip_dst":"192.168.1.10"},"tcp":{"tcp_tcp_srcport":"55321","tcp_tcp_dstport":"389"},"ldap":{"ldap_ldap_message_id":"1","ldap_ldap_protocol_op":"bindRequest"}}}`

	event, err := p.eventFromTsharkLine("Ethernet 2", line, now)
	if err != nil {
		t.Fatalf("eventFromTsharkLine() err = %v", err)
	}
	if event["EventType"] != "ldap" {
		t.Fatalf("EventType = %v, want ldap", event["EventType"])
	}
	if event["SrcIp"] != "192.168.7.2" || event["DstIp"] != "192.168.1.10" {
		t.Fatalf("unexpected endpoints: %#v", event)
	}
	if event["Protocol"] != "ldap" {
		t.Fatalf("unexpected protocol: %v", event["Protocol"])
	}
	if event["@timestamp"] != time.Date(2026, 4, 25, 8, 30, 0, 250000000, time.UTC).UnixMilli() {
		t.Fatalf("@timestamp = %v", event["@timestamp"])
	}
	if _, ok := event["ts"]; ok {
		t.Fatalf("unexpected ts field: %#v", event)
	}
	if _, ok := event["FrameProtocols"]; ok {
		t.Fatalf("unexpected FrameProtocols field: %#v", event)
	}

	layers, ok := event["ProtocolFields"].(map[string]any)
	if !ok {
		t.Fatalf("ProtocolFields missing or wrong type: %T", event["ProtocolFields"])
	}
	for _, layer := range []string{"frame", "ip", "tcp", "udp", "eth"} {
		if _, ok := layers[layer]; ok {
			t.Fatalf("ProtocolFields includes non-application layer %q: %#v", layer, layers)
		}
	}
	if _, ok := layers["ldap_ldap_message_id"]; !ok {
		ldap, ok := layers["ldap"].(map[string]any)
		if !ok {
			t.Fatalf("ProtocolFields does not include ldap details: %#v", layers)
		}
		if _, ok := ldap["ldap_ldap_message_id"]; !ok {
			t.Fatalf("ProtocolFields does not include ldap message id: %#v", layers)
		}
	}
	if _, err := json.Marshal(event); err != nil {
		t.Fatalf("event is not JSON-serializable: %v", err)
	}
}

func TestEventFromTsharkEKLineUsesLayerNamesForEventType(t *testing.T) {
	p := &tsharkPlugin{hostname: "DC01.example.local"}
	line := `{"layers":{"frame":{"frame_frame_time_epoch":"2026-04-25T08:31:00.000000000Z","frame_frame_protocols":"eth:ethertype:ip:udp:dns"},"ip":{"ip_ip_src":"192.168.1.10","ip_ip_dst":"192.168.1.1"},"udp":{"udp_udp_srcport":"61313","udp_udp_dstport":"53"},"dns":{"dns_dns_qry_name":"_ldap._tcp.dc._msdcs.sevenkingdoms.local","dns_dns_qry_type":"33"}}}`

	event, err := p.eventFromTsharkLine("Ethernet 2", line, time.Now())
	if err != nil {
		t.Fatalf("eventFromTsharkLine() err = %v", err)
	}
	if event["EventType"] != "dns" {
		t.Fatalf("EventType = %v, want dns", event["EventType"])
	}
	if event["Protocol"] != "dns" {
		t.Fatalf("Protocol = %v, want dns", event["Protocol"])
	}
}

func TestEventFromTsharkEKLineSkipsMetadata(t *testing.T) {
	p := &tsharkPlugin{hostname: "DC01.example.local"}
	event, err := p.eventFromTsharkLine("Ethernet 2", `{"index":{"_index":"packets"}}`, time.Now())
	if err != nil {
		t.Fatalf("eventFromTsharkLine() err = %v", err)
	}
	if len(event) != 0 {
		t.Fatalf("metadata line produced event: %#v", event)
	}
}

func TestEventFromTsharkEKLineFiltersProtocolFields(t *testing.T) {
	now := time.Date(2026, 4, 27, 17, 21, 22, 0, time.UTC)
	p := &tsharkPlugin{hostname: "DC01.example.local"}
	line := `{"layers":{"eth":{"eth_eth_dst":"ff:ff:ff:ff:ff:ff","eth_eth_src":"bc:24:11:00:e2:a0"},"frame":{"frame_frame_time_epoch":"2026-04-27T17:21:22.149774000Z","frame_frame_protocols":"eth:ethertype:ip:udp:nbns"},"ip":{"ip_ip_src":"192.168.1.10","ip_ip_dst":"192.168.1.255"},"udp":{"udp_udp_srcport":"137","udp_udp_dstport":"137"},"nbns":{"nbns_nbns_name":"WINTERFELL<00>","nbns_nbns_type":"32","text":["Queries","WINTERFELL<00>: type NB, class IN"]}}}`

	event, err := p.eventFromTsharkLine("Ethernet 2", line, now)
	if err != nil {
		t.Fatalf("eventFromTsharkLine() err = %v", err)
	}
	if event["EventType"] != "netbios" {
		t.Fatalf("EventType = %v, want netbios", event["EventType"])
	}
	if event["Protocol"] != "nbns" {
		t.Fatalf("Protocol = %v, want nbns", event["Protocol"])
	}
	if event["SrcIp"] != "192.168.1.10" || event["DstIp"] != "192.168.1.255" {
		t.Fatalf("unexpected endpoints: %#v", event)
	}
	if event["SrcPort"] != "137" || event["DstPort"] != "137" {
		t.Fatalf("unexpected ports: %#v", event)
	}
	if event["@timestamp"] != time.Date(2026, 4, 27, 17, 21, 22, 149774000, time.UTC).UnixMilli() {
		t.Fatalf("@timestamp = %v", event["@timestamp"])
	}

	layers, ok := event["ProtocolFields"].(map[string]any)
	if !ok {
		t.Fatalf("ProtocolFields missing or wrong type: %T", event["ProtocolFields"])
	}
	if len(layers) != 1 {
		t.Fatalf("ProtocolFields = %#v, want only nbns", layers)
	}
	if _, ok := layers["nbns"]; !ok {
		t.Fatalf("ProtocolFields missing nbns layer: %#v", layers)
	}
	for _, layer := range []string{"eth", "frame", "ip", "udp"} {
		if _, ok := layers[layer]; ok {
			t.Fatalf("ProtocolFields includes filtered layer %q: %#v", layer, layers)
		}
	}
}

func TestReadTsharkEKStreamDecodesMultipleObjects(t *testing.T) {
	p := &tsharkPlugin{hostname: "DC01.example.local"}
	stream := strings.NewReader(strings.Join([]string{
		`{"index":{"_index":"packets"}}`,
		`{"layers":{"frame":{"frame_frame_time_epoch":"2026-04-25T08:31:00.000000000Z","frame_frame_protocols":"eth:ethertype:ip:udp:dns"},"ip":{"ip_ip_src":"192.168.1.10","ip_ip_dst":"192.168.1.1"},"udp":{"udp_udp_srcport":"61313","udp_udp_dstport":"53"},"dns":{"dns_dns_qry_name":"sevenkingdoms.local","dns_dns_qry_type":"1"}}}`,
		`{"layers":{"frame":{"frame_frame_time_epoch":"2026-04-25T08:31:01.000000000Z","frame_frame_protocols":"eth:ethertype:ip:tcp:ldap"},"ip":{"ip_ip_src":"192.168.1.2","ip_ip_dst":"192.168.1.10"},"tcp":{"tcp_tcp_srcport":"55321","tcp_tcp_dstport":"389"},"ldap":{"ldap_ldap_messageID":"3","ldap_ldap_protocolOp":"2"}}}`,
	}, "\n"))

	var events []map[string]any
	err := p.readTsharkEKStream("Ethernet 2", stream, func(event map[string]any) {
		events = append(events, event)
	}, func() time.Time {
		return time.Date(2026, 4, 25, 8, 31, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatalf("readTsharkEKStream() err = %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("decoded %d events, want 2", len(events))
	}
	if events[0]["EventType"] != "dns" || events[1]["EventType"] != "ldap" {
		t.Fatalf("unexpected event types: %#v", events)
	}
	if events[1]["SrcIp"] != "192.168.1.2" || events[1]["DstPort"] != "389" {
		t.Fatalf("unexpected ldap event fields: %#v", events[1])
	}
}

func TestTsharkArgsForInterfaceIncludesADDecodeAs(t *testing.T) {
	p := &tsharkPlugin{
		captureFilter: "tcp port 88",
		displayFilter: "kerberos",
	}

	args := p.tsharkArgsForInterface("Ethernet 2")
	joined := strings.Join(args, "\x00")
	for _, want := range []string{
		"-i\x00Ethernet 2",
		"-f\x00tcp port 88",
		"-Y\x00kerberos",
		"-d\x00tcp.port==88,kerberos",
		"-d\x00udp.port==88,kerberos",
		"-d\x00tcp.port==135,dcerpc",
		"-d\x00tcp.port==3389,tpkt",
		"-T\x00ek",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("tshark args missing %q: %#v", want, args)
		}
	}
}
