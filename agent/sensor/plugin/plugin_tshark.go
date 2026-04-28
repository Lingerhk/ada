package plugin

import (
	"ada/agent/sensor/common"
	"ada/agent/sensor/stats"
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	logger "github.com/sirupsen/logrus"
)

const (
	defaultTsharkCaptureFilter = "(((tcp or udp) and (port 53 or port 88 or port 135 or port 137 or port 138 or port 139 or port 389 or port 445 or port 464 or port 593 or port 636 or port 3268 or port 3269 or port 3389)) or (tcp and portrange 49152-65535)) and (not (host %s))"
	defaultTsharkDisplayFilter = ""
	tsharkEventQueueSize       = 4096
	tsharkSenderWorkerCount    = 2
	tsharkStatsLogInterval     = 60 * time.Second
)

var defaultTsharkFields = []string{
	"frame.time_epoch",
	"frame.protocols",
	"ip.src",
	"ipv6.src",
	"ip.dst",
	"ipv6.dst",
	"tcp.srcport",
	"tcp.dstport",
	"udp.srcport",
	"udp.dstport",
	"_ws.col.protocol",
	"_ws.col.info",
	"dcerpc.cn_call_id",
	"dcerpc.cn_ctx_id",
	"dcerpc.cn_bind_to_uuid",
	"dcerpc.cn_bind_if_ver",
	"dcerpc.dg_if_id",
	"dcerpc.dg_if_ver",
	"dcerpc.opnum",
	"dcerpc.pkt_type",
	"dcerpc.cn_sec_addr",
	"epm.if_id",
	"epm.uuid",
	"epm.opnum",
	"epm.proto.ip",
	"epm.proto.tcp_port",
	"epm.proto.named_pipe",
}

var defaultTsharkDecodeAs = []string{
	"tcp.port==88,kerberos",
	"udp.port==88,kerberos",
	"tcp.port==464,kerberos",
	"udp.port==464,kerberos",
	"tcp.port==135,dcerpc",
	"tcp.port==593,dcerpc",
	"tcp.port==3389,tpkt",
	"tcp.port==389,ldap",
	"udp.port==389,cldap",
	"udp.port==137,nbns",
	"udp.port==138,nbdgm",
	"tcp.port==139,nbss",
}

type tsharkPlugin struct {
	parentCtx context.Context
	ctx       context.Context
	cancel    context.CancelFunc

	remoteHost    string
	syslogAddress string
	hostname      string

	mu            sync.RWMutex
	tsharkPath    string
	captureFilter string
	displayFilter string
	fields        []string
	IfaceNames    []string
	cmds          map[string]*exec.Cmd
	eventQueue    chan map[string]any
	wg            sync.WaitGroup

	decodedEvents uint64
	sentEvents    uint64
	droppedEvents uint64
	decodeErrors  uint64
	sendErrors    uint64
}

func NewTsharkPlugin(ctx context.Context, adaHost string, evtSrvPort int) (*tsharkPlugin, error) {
	return &tsharkPlugin{
		parentCtx:     ctx,
		remoteHost:    adaHost,
		syslogAddress: fmt.Sprintf("%s:%d", adaHost, evtSrvPort),
		hostname:      stats.GetFQDNName(),
		captureFilter: fmt.Sprintf(defaultTsharkCaptureFilter, adaHost),
		displayFilter: defaultTsharkDisplayFilter,
		fields:        append([]string(nil), defaultTsharkFields...),
		cmds:          make(map[string]*exec.Cmd),
	}, nil
}

func (p *tsharkPlugin) SetIfaceNames(ifaceNames []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.IfaceNames = append([]string(nil), ifaceNames...)
}

func (p *tsharkPlugin) GetIfaceNames() []string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]string(nil), p.IfaceNames...)
}

func (p *tsharkPlugin) SetConfig(path, captureFilter, displayFilter, fieldsCSV string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	changed := false
	if path != "" && path != p.tsharkPath {
		p.tsharkPath = path
		changed = true
	}
	if captureFilter != "" {
		if strings.Contains(captureFilter, "%s") {
			captureFilter = fmt.Sprintf(captureFilter, p.remoteHost)
		} else if !strings.Contains(captureFilter, p.remoteHost) {
			captureFilter = fmt.Sprintf("%s and (not (host %s))", captureFilter, p.remoteHost)
		}
		if captureFilter != p.captureFilter {
			p.captureFilter = captureFilter
			changed = true
		}
	}
	if displayFilter != "" && displayFilter != p.displayFilter {
		p.displayFilter = displayFilter
		changed = true
	}
	if fieldsCSV != "" {
		fields := splitCSV(fieldsCSV)
		if len(fields) > 0 && strings.Join(fields, ",") != strings.Join(p.fields, ",") {
			p.fields = fields
			changed = true
		}
	}

	return changed
}

func (p *tsharkPlugin) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.cmds) > 0 {
		return fmt.Errorf("tshark plugin already running")
	}
	if len(p.IfaceNames) == 0 {
		return fmt.Errorf("no interfaces specified for tshark")
	}

	tsharkPath, err := resolveTsharkPath(p.tsharkPath)
	if err != nil {
		return err
	}

	p.ctx, p.cancel = context.WithCancel(p.parentCtx)
	p.eventQueue = make(chan map[string]any, tsharkEventQueueSize)
	p.resetCountersLocked()
	p.startSenderWorkersLocked()
	p.startStatsReporterLocked()

	for _, iface := range p.IfaceNames {
		iface = strings.TrimSpace(iface)
		if iface == "" {
			continue
		}
		if err := p.startInterfaceLocked(tsharkPath, iface); err != nil {
			logger.Errorf("start tshark on %s err:%v", iface, err)
			continue
		}
	}

	if len(p.cmds) == 0 {
		if p.cancel != nil {
			p.cancel()
			p.cancel = nil
		}
		p.wg.Wait()
		p.eventQueue = nil
		return fmt.Errorf("failed to start tshark on any interface")
	}

	return nil
}

func (p *tsharkPlugin) startInterfaceLocked(tsharkPath, iface string) error {
	args := p.tsharkArgsForInterface(iface)

	cmd := exec.CommandContext(p.ctx, tsharkPath, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}

	p.cmds[iface] = cmd
	logger.Infof("started tshark plugin on iface=%s pid=%d filter=%q display=%q", iface, cmd.Process.Pid, p.captureFilter, p.displayFilter)

	p.wg.Add(3)
	go p.consumeStdout(iface, stdout)
	go p.consumeStderr(iface, stderr)
	go p.waitCmd(iface, cmd)

	return nil
}

func (p *tsharkPlugin) tsharkArgsForInterface(iface string) []string {
	args := []string{"-l", "-n", "-i", iface}
	if p.captureFilter != "" {
		args = append(args, "-f", p.captureFilter)
	}
	if p.displayFilter != "" {
		args = append(args, "-Y", p.displayFilter)
	}
	for _, decodeAs := range defaultTsharkDecodeAs {
		args = append(args, "-d", decodeAs)
	}
	args = append(args, "-T", "ek")
	return args
}

func (p *tsharkPlugin) consumeStdout(iface string, stdout io.Reader) {
	defer p.wg.Done()

	if err := p.readTsharkEKStream(iface, stdout, p.enqueueTsharkEvent, time.Now); err != nil && p.ctx.Err() == nil {
		logger.Warnf("read tshark stdout iface=%s err:%v", iface, err)
	}
}

func (p *tsharkPlugin) readTsharkEKStream(iface string, stdout io.Reader, emit func(map[string]any), now func() time.Time) error {
	decoder := json.NewDecoder(stdout)
	for {
		var record map[string]any
		if err := decoder.Decode(&record); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			atomic.AddUint64(&p.decodeErrors, 1)
			return err
		}

		event, err := p.eventFromTsharkEKRecord(iface, record, now())
		if err != nil {
			errCount := atomic.AddUint64(&p.decodeErrors, 1)
			if errCount == 1 || errCount%1000 == 0 {
				logger.Warnf("decode tshark event iface=%s err:%v decode_errors=%d", iface, err, errCount)
			}
			continue
		}
		if len(event) == 0 {
			continue
		}
		atomic.AddUint64(&p.decodedEvents, 1)
		emit(event)
	}
}

func (p *tsharkPlugin) consumeStderr(iface string, stderr io.Reader) {
	defer p.wg.Done()

	scanner := bufio.NewScanner(stderr)
	scanner.Buffer(make([]byte, 16*1024), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			logger.Warnf("tshark[%s]: %s", iface, line)
		}
	}
}

func (p *tsharkPlugin) waitCmd(iface string, cmd *exec.Cmd) {
	defer p.wg.Done()

	err := cmd.Wait()
	p.mu.Lock()
	delete(p.cmds, iface)
	p.mu.Unlock()

	if p.ctx.Err() != nil {
		return
	}
	if err != nil {
		logger.Errorf("tshark iface=%s exited err:%v", iface, err)
		return
	}
	logger.Infof("tshark iface=%s exited", iface)
}

func (p *tsharkPlugin) handleTsharkLine(iface, line string) error {
	event, err := p.eventFromTsharkLine(iface, line, time.Now())
	if err != nil {
		return err
	}
	if len(event) == 0 {
		return nil
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}

	return p.sendSyslog(string(payload))
}

func (p *tsharkPlugin) enqueueTsharkEvent(event map[string]any) {
	p.mu.RLock()
	queue := p.eventQueue
	ctx := p.ctx
	p.mu.RUnlock()

	if queue == nil || ctx == nil {
		dropped := atomic.AddUint64(&p.droppedEvents, 1)
		if dropped == 1 || dropped%1000 == 0 {
			logger.Warnf("drop tshark event because sender queue is not available dropped=%d", dropped)
		}
		return
	}

	select {
	case queue <- event:
	case <-ctx.Done():
		atomic.AddUint64(&p.droppedEvents, 1)
	default:
		dropped := atomic.AddUint64(&p.droppedEvents, 1)
		if dropped == 1 || dropped%1000 == 0 {
			logger.Warnf("drop tshark event because sender queue is full queue_len=%d queue_cap=%d dropped=%d", len(queue), cap(queue), dropped)
		}
	}
}

func (p *tsharkPlugin) startSenderWorkersLocked() {
	for i := 0; i < tsharkSenderWorkerCount; i++ {
		workerID := i
		ctx := p.ctx
		queue := p.eventQueue
		p.wg.Add(1)
		go p.tsharkSenderWorker(ctx, queue, workerID)
	}
}

func (p *tsharkPlugin) tsharkSenderWorker(ctx context.Context, queue <-chan map[string]any, workerID int) {
	defer p.wg.Done()

	for {
		select {
		case event := <-queue:
			p.sendTsharkEvent(workerID, event)
		case <-ctx.Done():
			p.drainTsharkQueue(workerID, queue)
			return
		}
	}
}

func (p *tsharkPlugin) drainTsharkQueue(workerID int, queue <-chan map[string]any) {
	for {
		select {
		case event := <-queue:
			p.sendTsharkEvent(workerID, event)
		default:
			return
		}
	}
}

func (p *tsharkPlugin) sendTsharkEvent(workerID int, event map[string]any) {
	payload, err := json.Marshal(event)
	if err != nil {
		errCount := atomic.AddUint64(&p.sendErrors, 1)
		if errCount == 1 || errCount%1000 == 0 {
			logger.Warnf("marshal tshark event failed worker=%d err:%v send_errors=%d", workerID, err, errCount)
		}
		return
	}
	if err := p.sendSyslog(string(payload)); err != nil {
		errCount := atomic.AddUint64(&p.sendErrors, 1)
		if errCount == 1 || errCount%1000 == 0 {
			logger.Warnf("send tshark event failed worker=%d err:%v send_errors=%d", workerID, err, errCount)
		}
		return
	}
	atomic.AddUint64(&p.sentEvents, 1)
}

func (p *tsharkPlugin) startStatsReporterLocked() {
	ctx := p.ctx
	queue := p.eventQueue
	p.wg.Add(1)
	go p.reportTsharkStats(ctx, queue)
}

func (p *tsharkPlugin) reportTsharkStats(ctx context.Context, queue <-chan map[string]any) {
	defer p.wg.Done()

	ticker := time.NewTicker(tsharkStatsLogInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			logger.Infof("tshark stats decoded=%d sent=%d dropped=%d decode_errors=%d send_errors=%d queue_len=%d queue_cap=%d",
				atomic.LoadUint64(&p.decodedEvents),
				atomic.LoadUint64(&p.sentEvents),
				atomic.LoadUint64(&p.droppedEvents),
				atomic.LoadUint64(&p.decodeErrors),
				atomic.LoadUint64(&p.sendErrors),
				len(queue),
				cap(queue),
			)
		case <-ctx.Done():
			return
		}
	}
}

func (p *tsharkPlugin) resetCountersLocked() {
	atomic.StoreUint64(&p.decodedEvents, 0)
	atomic.StoreUint64(&p.sentEvents, 0)
	atomic.StoreUint64(&p.droppedEvents, 0)
	atomic.StoreUint64(&p.decodeErrors, 0)
	atomic.StoreUint64(&p.sendErrors, 0)
}

func (p *tsharkPlugin) eventFromTsharkLine(iface, line string, now time.Time) (map[string]any, error) {
	if strings.HasPrefix(strings.TrimSpace(line), "{") {
		return p.eventFromTsharkEKLine(iface, line, now)
	}
	return p.eventFromTsharkFieldsLine(iface, line, now)
}

func (p *tsharkPlugin) eventFromTsharkEKLine(iface, line string, now time.Time) (map[string]any, error) {
	var record map[string]any
	if err := json.Unmarshal([]byte(line), &record); err != nil {
		return nil, err
	}
	return p.eventFromTsharkEKRecord(iface, record, now)
}

func (p *tsharkPlugin) eventFromTsharkEKRecord(iface string, record map[string]any, now time.Time) (map[string]any, error) {
	layers, ok := record["layers"].(map[string]any)
	if !ok || len(layers) == 0 {
		return nil, nil
	}

	event := make(map[string]any, len(layers)+16)
	event["ProtocolFields"] = layers

	setFirstLayerValue(event, "FrameTimeEpoch", layers, "frame_frame_time_epoch", "frame.time_epoch", "frame_frame_time_epoch_raw")
	setFirstLayerValue(event, "FrameProtocols", layers, "frame_frame_protocols", "frame.protocols")
	setFirstLayerValue(event, "SrcIp", layers, "ip_ip_src", "ip.src", "ipv6_ipv6_src", "ipv6.src")
	setFirstLayerValue(event, "DstIp", layers, "ip_ip_dst", "ip.dst", "ipv6_ipv6_dst", "ipv6.dst")
	setFirstLayerValue(event, "SrcPort", layers, "tcp_tcp_srcport", "tcp.srcport", "udp_udp_srcport", "udp.srcport")
	setFirstLayerValue(event, "DstPort", layers, "tcp_tcp_dstport", "tcp.dstport", "udp_udp_dstport", "udp.dstport")
	setFirstLayerValue(event, "Protocol", layers, "_ws_col_Protocol", "_ws.col.Protocol", "_ws_col_protocol", "_ws.col.protocol")
	setFirstLayerValue(event, "Info", layers, "_ws_col_Info", "_ws.col.Info", "_ws_col_info", "_ws.col.info")
	setFirstLayerValue(event, "RpcInterfaceUuid", layers, "dcerpc_dcerpc_cn_bind_to_uuid", "dcerpc.cn_bind_to_uuid", "dcerpc_dcerpc_dg_if_id", "dcerpc.dg_if_id", "epm_epm_if_id", "epm.if_id", "epm_epm_uuid", "epm.uuid")
	setFirstLayerValue(event, "RpcInterfaceVersion", layers, "dcerpc_dcerpc_cn_bind_if_ver", "dcerpc.cn_bind_if_ver", "dcerpc_dcerpc_dg_if_ver", "dcerpc.dg_if_ver")
	setFirstLayerValue(event, "RpcOpnum", layers, "dcerpc_dcerpc_opnum", "dcerpc.opnum", "epm_epm_opnum", "epm.opnum")
	setFirstLayerValue(event, "RpcPacketType", layers, "dcerpc_dcerpc_pkt_type", "dcerpc.pkt_type")
	setFirstLayerValue(event, "RpcEndpoint", layers, "dcerpc_dcerpc_cn_sec_addr", "dcerpc.cn_sec_addr", "epm_epm_proto_tcp_port", "epm.proto.tcp_port")
	setFirstLayerValue(event, "RpcEndpointIp", layers, "epm_epm_proto_ip", "epm.proto.ip")
	setFirstLayerValue(event, "RpcNamedPipe", layers, "epm_epm_proto_named_pipe", "epm.proto.named_pipe")

	if stringFromEvent(event, "Protocol") == "" {
		event["Protocol"] = protocolFromLayers(layers, stringFromEvent(event, "FrameProtocols"))
	}

	eventType := eventTypeFromTsharkEvent(event)
	if eventType == "" {
		return nil, nil
	}

	protocolFields := protocolFieldsFromTsharkLayers(layers, eventType, stringFromEvent(event, "Protocol"))

	event["LogType"] = "pktlog"
	event["Source"] = "tshark"
	event["EventType"] = eventType
	event["Hostname"] = p.hostname
	event["Iface"] = iface
	event["SensorTime"] = strconv.FormatInt(now.Unix(), 10)
	event["@timestamp"] = normalizeTsharkTimestamp(stringFromEvent(event, "FrameTimeEpoch"), now)
	if len(protocolFields) > 0 {
		event["ProtocolFields"] = protocolFields
	} else {
		delete(event, "ProtocolFields")
	}
	delete(event, "FrameTimeEpoch")
	delete(event, "FrameProtocols")

	return event, nil
}

func (p *tsharkPlugin) eventFromTsharkFieldsLine(iface, line string, now time.Time) (map[string]any, error) {
	p.mu.RLock()
	fields := append([]string(nil), p.fields...)
	p.mu.RUnlock()

	values := strings.Split(line, "\t")
	event := make(map[string]any, len(fields)+12)
	for i, field := range fields {
		val := ""
		if i < len(values) {
			val = strings.TrimSpace(values[i])
		}
		if val == "" {
			continue
		}
		event[normalizeTsharkField(field)] = val
	}

	protocol, _ := event["Protocol"].(string)
	if protocol == "" {
		protocol = eventTypeFromTsharkEvent(event)
		event["Protocol"] = protocol
	}

	eventType := eventTypeFromTsharkEvent(event)
	if eventType == "" {
		return nil, nil
	}

	event["LogType"] = "pktlog"
	event["Source"] = "tshark"
	event["EventType"] = eventType
	event["Hostname"] = p.hostname
	event["Iface"] = iface
	event["SensorTime"] = strconv.FormatInt(now.Unix(), 10)

	if _, ok := event["SrcIp"]; !ok {
		if v, ok := event["SrcIpV6"]; ok {
			event["SrcIp"] = v
		}
	}
	if _, ok := event["DstIp"]; !ok {
		if v, ok := event["DstIpV6"]; ok {
			event["DstIp"] = v
		}
	}
	event["@timestamp"] = normalizeTsharkTimestamp(stringFromEvent(event, "FrameTimeEpoch"), now)
	delete(event, "FrameTimeEpoch")
	delete(event, "FrameProtocols")

	return event, nil
}

func (p *tsharkPlugin) sendSyslog(content string) error {
	addr, err := net.ResolveUDPAddr("udp", p.syslogAddress)
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	ts := time.Now().Format("Jan _2 15:04:05")
	msg := fmt.Sprintf("<14>%s %s ADASensor: %s", ts, p.hostname, content)
	_, err = conn.Write([]byte(msg))
	return err
}

func (p *tsharkPlugin) Stop() error {
	p.mu.Lock()
	cancel := p.cancel
	p.mu.Unlock()

	if cancel == nil {
		return nil
	}
	cancel()
	p.wg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()
	p.cancel = nil
	p.cmds = make(map[string]*exec.Cmd)
	p.eventQueue = nil
	return nil
}

func (p *tsharkPlugin) Reload() error {
	if !p.IsRunning() {
		return fmt.Errorf("tshark plugin not running")
	}
	if err := p.Stop(); err != nil {
		return err
	}
	return p.Start()
}

func (p *tsharkPlugin) IsRunning() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.cmds) > 0
}

func (p *tsharkPlugin) PrimaryPID() uint32 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	for _, cmd := range p.cmds {
		if cmd != nil && cmd.Process != nil {
			return uint32(cmd.Process.Pid)
		}
	}
	return 0
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func resolveTsharkPath(configured string) (string, error) {
	candidates := []string{}
	if strings.TrimSpace(configured) != "" {
		candidates = append(candidates, strings.TrimSpace(configured))
	}
	candidates = append(candidates,
		filepath.Join(common.SensorDir, "tshark", "tshark.exe"),
		`C:\Program Files\Wireshark\tshark.exe`,
		`C:\Program Files (x86)\Wireshark\tshark.exe`,
		"tshark.exe",
	)

	for _, candidate := range candidates {
		if filepath.IsAbs(candidate) {
			if _, err := exec.LookPath(candidate); err == nil {
				return candidate, nil
			}
			continue
		}
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("tshark executable not found")
}

func normalizeTsharkField(field string) string {
	switch field {
	case "frame.time_epoch":
		return "FrameTimeEpoch"
	case "frame.protocols":
		return "FrameProtocols"
	case "ip.src":
		return "SrcIp"
	case "ipv6.src":
		return "SrcIpV6"
	case "ip.dst":
		return "DstIp"
	case "ipv6.dst":
		return "DstIpV6"
	case "tcp.srcport":
		return "SrcPort"
	case "tcp.dstport":
		return "DstPort"
	case "udp.srcport":
		return "SrcPort"
	case "udp.dstport":
		return "DstPort"
	case "_ws.col.protocol":
		return "Protocol"
	case "_ws.col.info":
		return "Info"
	case "dcerpc.cn_call_id":
		return "RpcCallId"
	case "dcerpc.cn_ctx_id":
		return "RpcContextId"
	case "dcerpc.cn_bind_to_uuid", "dcerpc.dg_if_id", "epm.if_id", "epm.uuid":
		return "RpcInterfaceUuid"
	case "dcerpc.cn_bind_if_ver", "dcerpc.dg_if_ver":
		return "RpcInterfaceVersion"
	case "dcerpc.opnum", "epm.opnum":
		return "RpcOpnum"
	case "dcerpc.pkt_type":
		return "RpcPacketType"
	case "dcerpc.cn_sec_addr", "epm.proto.tcp_port":
		return "RpcEndpoint"
	case "epm.proto.ip":
		return "RpcEndpointIp"
	case "epm.proto.named_pipe":
		return "RpcNamedPipe"
	default:
		return strings.NewReplacer(".", "_", "-", "_").Replace(field)
	}
}

func eventTypeFromTsharkEvent(event map[string]any) string {
	protocol := strings.ToLower(stringFromEvent(event, "Protocol") + ":" + stringFromEvent(event, "FrameProtocols"))
	if layers, ok := event["ProtocolFields"].(map[string]any); ok {
		protocol += ":" + protocolNamesFromLayers(layers)
	}
	switch {
	case containsAny(protocol, "dcerpc", "dce/rpc", "epm"):
		return "dcerpc"
	case containsAny(protocol, "ldap", "cldap"):
		return "ldap"
	case containsAny(protocol, "smb2", "smb3"):
		return "smb2"
	case strings.Contains(protocol, "smb"):
		return "smb"
	case containsAny(protocol, "kerberos", "krb5"):
		return "kerberos"
	case strings.Contains(protocol, "ntlmssp"):
		return "ntlm"
	case strings.Contains(protocol, "dns"):
		return "dns"
	case containsAny(protocol, "rdp", "tpkt", "cotp"):
		return "rdp"
	case containsAny(protocol, "nbns", "nbss", "nbdgm", "netbios"):
		return "netbios"
	}

	for _, key := range []string{"RpcInterfaceUuid", "RpcOpnum", "RpcPacketType", "RpcEndpoint"} {
		if v, ok := event[key].(string); ok && v != "" {
			return "dcerpc"
		}
	}

	srcPort := stringFromEvent(event, "SrcPort")
	dstPort := stringFromEvent(event, "DstPort")
	if srcPort != "" || dstPort != "" {
		if typ := eventTypeFromPorts(srcPort, dstPort); typ != "" {
			return typ
		}
	}
	return ""
}

func eventTypeFromPorts(ports ...string) string {
	for _, port := range ports {
		switch strings.TrimSpace(port) {
		case "53":
			return "dns"
		case "88":
			return "kerberos"
		case "135", "593":
			return "dcerpc"
		case "137", "138":
			return "netbios"
		case "139":
			return "smb"
		case "389", "636", "3268", "3269":
			return "ldap"
		case "445":
			return "smb2"
		case "464":
			return "kerberos"
		case "3389":
			return "rdp"
		}
	}
	return ""
}

func stringFromEvent(event map[string]any, key string) string {
	if v, ok := event[key].(string); ok {
		return v
	}
	return ""
}

func setFirstLayerValue(event map[string]any, eventKey string, layers map[string]any, layerKeys ...string) {
	if val := firstLayerString(layers, layerKeys...); val != "" {
		event[eventKey] = val
	}
}

func firstLayerString(layers map[string]any, keys ...string) string {
	for _, key := range keys {
		if val, ok := lookupLayerValue(layers, key); ok {
			if s := tsharkValueToString(val); s != "" {
				return s
			}
		}
	}
	return ""
}

func lookupLayerValue(layers map[string]any, key string) (any, bool) {
	if val, ok := layers[key]; ok {
		return val, true
	}

	normalized := normalizeTsharkFieldKey(key)
	if normalized != key {
		if val, ok := layers[normalized]; ok {
			return val, true
		}
	}

	for _, candidate := range []string{key, normalized} {
		layerName := layerNameFromFieldKey(candidate)
		if layerName == "" {
			continue
		}
		layer, ok := layers[layerName].(map[string]any)
		if !ok {
			continue
		}
		if val, ok := layer[candidate]; ok {
			return val, true
		}
	}

	for _, layerRaw := range layers {
		layer, ok := layerRaw.(map[string]any)
		if !ok {
			continue
		}
		if val, ok := layer[key]; ok {
			return val, true
		}
		if normalized != key {
			if val, ok := layer[normalized]; ok {
				return val, true
			}
		}
	}

	return nil, false
}

func normalizeTsharkFieldKey(key string) string {
	return strings.NewReplacer(".", "_", "-", "_").Replace(key)
}

func layerNameFromFieldKey(key string) string {
	if key == "" || strings.HasPrefix(key, "_") {
		return ""
	}
	idx := strings.Index(key, "_")
	if idx <= 0 {
		return key
	}
	return key[:idx]
}

func tsharkValueToString(v any) string {
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val)
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(val)
	case []any:
		for _, item := range val {
			if s := tsharkValueToString(item); s != "" {
				return s
			}
		}
	case map[string]any:
		for _, key := range []string{"show", "value", "_ws.expert.message"} {
			if item, ok := val[key]; ok {
				if s := tsharkValueToString(item); s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func protocolFromLayers(layers map[string]any, frameProtocols string) string {
	layerNames := protocolNamesFromLayers(layers)
	for _, protocol := range []string{"dcerpc", "epm", "ldap", "cldap", "smb2", "smb", "kerberos", "krb5", "ntlmssp", "dns", "rdp", "tpkt", "cotp", "nbns", "nbss", "nbdgm"} {
		if containsAny(layerNames, protocol) {
			return protocol
		}
	}
	parts := strings.Split(frameProtocols, ":")
	if len(parts) > 0 {
		return strings.TrimSpace(parts[len(parts)-1])
	}
	return ""
}

func protocolNamesFromLayers(layers map[string]any) string {
	names := make([]string, 0, len(layers))
	for key := range layers {
		names = append(names, strings.ToLower(key))
	}
	return strings.Join(names, ":")
}

func protocolFieldsFromTsharkLayers(layers map[string]any, eventType, protocol string) map[string]any {
	allowed := tsharkProtocolLayerSet(eventType, protocol)
	filtered := make(map[string]any, len(layers))
	for key, val := range layers {
		layerName := strings.ToLower(strings.TrimSpace(key))
		if allowed[layerName] {
			filtered[key] = val
		}
	}
	return filtered
}

func tsharkProtocolLayerSet(eventType, protocol string) map[string]bool {
	allowed := map[string]bool{}
	add := func(names ...string) {
		for _, name := range names {
			name = strings.ToLower(strings.TrimSpace(name))
			if name != "" {
				allowed[name] = true
			}
		}
	}

	add(eventType, protocol)
	switch eventType {
	case "dcerpc":
		add("dcerpc", "epm")
	case "ldap":
		add("ldap", "cldap")
	case "smb2":
		add("smb2")
	case "smb":
		add("smb", "smb2")
	case "kerberos":
		add("kerberos", "krb5")
	case "ntlm":
		add("ntlmssp")
	case "dns":
		add("dns")
	case "rdp":
		add("rdp", "tpkt", "cotp")
	case "netbios":
		add("nbns", "nbss", "nbdgm", "netbios")
	}
	return allowed
}

func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func normalizeTsharkTimestamp(frameTimeEpoch string, fallback time.Time) int64 {
	frameTimeEpoch = strings.TrimSpace(frameTimeEpoch)
	if ts, err := time.Parse(time.RFC3339Nano, frameTimeEpoch); err == nil {
		return ts.UTC().UnixMilli()
	}

	epoch, err := strconv.ParseFloat(frameTimeEpoch, 64)
	if err != nil || epoch <= 0 {
		return fallback.UTC().UnixMilli()
	}

	sec := int64(epoch)
	nsec := int64((epoch - float64(sec)) * 1e9)
	if nsec < 0 {
		nsec = 0
	}
	return time.Unix(sec, nsec).UTC().UnixMilli()
}
