package client

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"cottendns-go/internal/config"
	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
)

func hostileDNSResponse(query []byte, rcode uint8) []byte {
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8100|uint16(rcode&0x0f))
	return response
}

func TestSynchronousUDPProbeSurvivesPoisonRace(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientConn, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.Close()

	query, err := DnsParser.BuildTXTQuestionPacket("probe.tunnel.example", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		buffer := make([]byte, 4096)
		n, peer, readErr := server.ReadFromUDP(buffer)
		if readErr != nil {
			done <- readErr
			return
		}
		request := append([]byte(nil), buffer[:n]...)
		if _, writeErr := server.WriteToUDP(hostileDNSResponse(request, Enums.DNSR_CODE_NAME_ERROR), peer); writeErr != nil {
			done <- writeErr
			return
		}
		time.Sleep(10 * time.Millisecond)
		_, writeErr := server.WriteToUDP(hostileDNSResponse(request, 0), peer)
		done <- writeErr
	}()

	c := &Client{cfg: config.ClientConfig{ResolverIgnoreInjectedNXDOMAIN: true}}
	c.runtimeReadBufferSize = 4096
	c.udpBufferPool.New = func() any { return make([]byte, 4096) }
	response, err := c.exchangeUDPQueryWithConn(clientConn, query, time.Second)
	if err != nil {
		t.Fatalf("poison race blocked the genuine UDP response: %v", err)
	}
	parsed, err := DnsParser.ParsePacketLite(response)
	if err != nil || parsed.Header.RCode != 0 {
		t.Fatalf("returned poisoned response instead of genuine answer: rcode=%d err=%v", parsed.Header.RCode, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSynchronousTCPProbeRejectsHijackedQuestion(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer clientSide.Close()
	defer serverSide.Close()

	query, err := DnsParser.BuildTXTQuestionPacket("probe.tunnel.example", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		request, readErr := readTCPDNSFramed(serverSide)
		if readErr != nil {
			done <- readErr
			return
		}
		hijack, buildErr := DnsParser.BuildTXTQuestionPacket("block.invalid", Enums.DNS_RECORD_TYPE_TXT, 0)
		if buildErr != nil {
			done <- buildErr
			return
		}
		binary.BigEndian.PutUint16(hijack[:2], binary.BigEndian.Uint16(request[:2]))
		hijack = hostileDNSResponse(hijack, 0)
		if writeErr := writeTCPDNSFramed(serverSide, hijack); writeErr != nil {
			done <- writeErr
			return
		}
		done <- writeTCPDNSFramed(serverSide, hostileDNSResponse(request, 0))
	}()

	transport := &tcpQueryTransport{client: &Client{}, conn: clientSide}
	response, err := transport.exchange(query, time.Second)
	if err != nil {
		t.Fatalf("hijacked TCP question blocked the genuine response: %v", err)
	}
	if dnsQuestionFingerprint(response) != dnsQuestionFingerprint(query) {
		t.Fatal("TCP exchanger returned the mismatched hijack response")
	}
	if err := <-done; err != nil && err != io.EOF {
		t.Fatal(err)
	}
}

func TestOutstandingQueriesWithSameTXIDStayIndependent(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.resolverPending = make(map[resolverSampleKey]resolverSample)
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.53"), Port: 53}
	first, err := DnsParser.BuildTXTQuestionPacket("first.tunnel.example", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DnsParser.BuildTXTQuestionPacket("second.tunnel.example", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	binary.BigEndian.PutUint16(second[:2], binary.BigEndian.Uint16(first[:2]))
	now := time.Now()
	c.trackResolverSendOver(first, addr.String(), "local", "resolver-a", transportUDP, now)
	c.trackResolverSendOver(second, addr.String(), "local", "resolver-a", transportUDP, now)
	if len(c.resolverPending) != 2 {
		t.Fatalf("same-TXID queries collided: pending=%d, want 2", len(c.resolverPending))
	}
	if !c.trackResolverSuccessOver(first, addr, "local", transportUDP, now.Add(20*time.Millisecond)) {
		t.Fatal("first same-TXID response was not claimed")
	}
	if len(c.resolverPending) != 1 {
		t.Fatalf("claiming first query removed its distinct sibling: pending=%d", len(c.resolverPending))
	}
	if !c.trackResolverSuccessOver(second, addr, "local", transportUDP, now.Add(30*time.Millisecond)) {
		t.Fatal("second same-TXID response was not claimed")
	}
}

func TestQuestionFingerprintAcceptsDNSCaseNormalization(t *testing.T) {
	query, err := DnsParser.BuildTXTQuestionPacket("MiXeD.tunnel.example", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	normalized := append([]byte(nil), query...)
	for offset := 13; offset < len(normalized); offset++ {
		if normalized[offset] >= 'A' && normalized[offset] <= 'Z' {
			normalized[offset] += 'a' - 'A'
		}
	}
	if got, want := dnsQuestionFingerprint(normalized), dnsQuestionFingerprint(query); got == 0 || got != want {
		t.Fatalf("case-normalized DNS question fingerprint=%x, want=%x", got, want)
	}
}

func TestUDPTruncationImmediatelyPrefersTCP(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.resolverPending = make(map[resolverSampleKey]resolverSample)
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.75"), Port: 53}
	query, err := DnsParser.BuildTXTQuestionPacket("payload.tunnel.example", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c.trackResolverSendOver(query, addr.String(), "udp-local", "resolver-a", transportUDP, now)

	truncated := append([]byte(nil), query...)
	truncated[2] |= 0x80 // QR
	truncated[2] |= 0x02 // TC
	c.handleInboundPacketOver(truncated, addr, "udp-local", transportUDP)

	if got := c.preferredResolverTransport("resolver-a"); got != transportTCP {
		t.Fatalf("UDP TC response did not immediately prefer TCP: got %s", got)
	}
}

func TestPoisonSignalImmediatelyRacesAlternateAndFirstResponseWins(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.resolverPending = make(map[resolverSampleKey]resolverSample)
	c.resolverAddrCache = make(map[string]*net.UDPAddr)
	c.resolverHealth = make(map[string]*resolverHealthState)
	c.encodedTXChannel = make(chan encodedOutboundTask, 2)
	c.connections = []Connection{{
		Key: "resolver-a", Domain: "tunnel.example", Resolver: "192.0.2.75",
		ResolverPort: 53, IsValid: true, UploadMTUBytes: 220, DownloadMTUBytes: 1200,
	}}
	c.connectionsByKey = map[string]int{"resolver-a": 0}
	c.balancer = NewBalancer(BalancingRoundRobinDefault)
	c.balancer.SetConnections([]*Connection{&c.connections[0]})

	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.75"), Port: 53}
	query, err := DnsParser.BuildTXTQuestionPacket("payload.tunnel.example", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	frame := encodedOutboundDatagram{
		addr: addr, serverKey: "resolver-a", packet: query,
		priority: Enums.PacketPriorityNormal, transport: transportUDP,
		packetType: Enums.PACKET_STREAM_DATA, payloadSize: 80,
	}
	now := time.Now()
	c.trackResolverFrameOver(frame, "udp-local", transportUDP, now)
	c.noteInjectedResolverNoise(hostileDNSResponse(query, Enums.DNSR_CODE_NAME_ERROR), addr, "udp-local", transportUDP)

	var replay encodedOutboundDatagram
	select {
	case task := <-c.encodedTXChannel:
		if len(task.frames) != 1 {
			t.Fatalf("poison replay frame count=%d, want 1", len(task.frames))
		}
		replay = task.frames[0]
	default:
		t.Fatal("poison signal did not immediately queue an alternate path")
	}
	if replay.transport != transportTCP || replay.replayDepth != 1 {
		t.Fatalf("poison replay=%+v, want one-hop TCP alternate", replay)
	}

	c.trackResolverFrameOver(replay, "tcp-local", replay.transport, now.Add(time.Millisecond))
	response := hostileDNSResponse(query, 0)
	if !c.trackResolverSuccessOver(response, addr, "tcp-local", transportTCP, now.Add(20*time.Millisecond)) {
		t.Fatal("authenticated alternate response did not win")
	}
	if c.trackResolverSuccessOver(response, addr, "udp-local", transportUDP, now.Add(30*time.Millisecond)) {
		t.Fatal("slower original response won after the alternate was claimed")
	}
	if len(c.resolverPending) != 0 {
		t.Fatalf("logical replay siblings remained pending: %d", len(c.resolverPending))
	}
}

func TestExpiredPathReplaysFrameBeforeARQRetry(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.resolverPending = make(map[resolverSampleKey]resolverSample)
	c.resolverAddrCache = make(map[string]*net.UDPAddr)
	c.resolverHealth = make(map[string]*resolverHealthState)
	c.encodedTXChannel = make(chan encodedOutboundTask, 2)
	c.tunnelPacketTimeout = 500 * time.Millisecond
	c.connections = []Connection{{
		Key: "resolver-a", Domain: "tunnel.example", Resolver: "192.0.2.75",
		ResolverPort: 53, IsValid: true, UploadMTUBytes: 220, DownloadMTUBytes: 1200,
	}}
	c.connectionsByKey = map[string]int{"resolver-a": 0}
	c.balancer = NewBalancer(BalancingRoundRobinDefault)
	c.balancer.SetConnections([]*Connection{&c.connections[0]})

	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.75"), Port: 53}
	query, err := DnsParser.BuildTXTQuestionPacket("payload.tunnel.example", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	sentAt := time.Now().Add(-time.Second)
	c.trackResolverFrameOver(encodedOutboundDatagram{
		addr: addr, serverKey: "resolver-a", packet: query,
		priority: Enums.PacketPriorityNormal, transport: transportUDP,
		packetType: Enums.PACKET_STREAM_DATA, payloadSize: 80,
	}, "udp-local", transportUDP, sentAt)

	c.collectExpiredResolverTimeouts(time.Now())
	select {
	case task := <-c.encodedTXChannel:
		if len(task.frames) != 1 || task.frames[0].replayDepth != 1 || task.frames[0].transport != transportTCP {
			t.Fatalf("timeout replay did not preserve and reroute the frame: %+v", task.frames)
		}
	default:
		t.Fatal("failed path waited for ARQ instead of replaying the in-flight frame")
	}
}

func TestOriginalWinnerCancelsQueuedPoisonReplay(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.resolverPending = make(map[resolverSampleKey]resolverSample)
	c.resolverCompleted = make(map[resolverCompletedKey]time.Time)
	c.resolverAddrCache = make(map[string]*net.UDPAddr)
	c.resolverHealth = make(map[string]*resolverHealthState)
	c.encodedTXChannel = make(chan encodedOutboundTask, 1)
	c.connections = []Connection{{
		Key: "resolver-a", Domain: "tunnel.example", Resolver: "192.0.2.75",
		ResolverPort: 53, IsValid: true, UploadMTUBytes: 220, DownloadMTUBytes: 1200,
	}}
	c.connectionsByKey = map[string]int{"resolver-a": 0}
	c.balancer = NewBalancer(BalancingRoundRobinDefault)
	c.balancer.SetConnections([]*Connection{&c.connections[0]})

	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.75"), Port: 53}
	query, err := DnsParser.BuildTXTQuestionPacket("payload.tunnel.example", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c.trackResolverFrameOver(encodedOutboundDatagram{
		addr: addr, serverKey: "resolver-a", packet: query,
		priority: Enums.PacketPriorityNormal, transport: transportUDP,
		packetType: Enums.PACKET_STREAM_DATA, payloadSize: 80,
	}, "udp-local", transportUDP, now)
	c.noteInjectedResolverNoise(hostileDNSResponse(query, Enums.DNSR_CODE_NAME_ERROR), addr, "udp-local", transportUDP)
	if !c.trackResolverSuccessOver(hostileDNSResponse(query, 0), addr, "udp-local", transportUDP, now.Add(10*time.Millisecond)) {
		t.Fatal("genuine original response did not win")
	}
	task := <-c.encodedTXChannel
	if len(task.frames) != 1 || !c.resolverReplayCompleted(task.frames[0], now.Add(11*time.Millisecond)) {
		t.Fatal("queued poison replay was not cancelled after the original won")
	}
}

func TestPoisonReplayRanksAllPathsByDeliveredSpeed(t *testing.T) {
	c := newAutoTransportPolicyClient()
	c.resolverPending = make(map[resolverSampleKey]resolverSample)
	c.resolverAddrCache = make(map[string]*net.UDPAddr)
	c.encodedTXChannel = make(chan encodedOutboundTask, 1)
	c.connections = []Connection{
		{
			Key: "resolver-a", Domain: "tunnel.example", Resolver: "192.0.2.75",
			ResolverPort: 53, IsValid: true, UploadMTUBytes: 220, DownloadMTUBytes: 1200,
			MTUResolveTime: 300 * time.Millisecond,
		},
		{
			Key: "resolver-b", Domain: "tunnel.example", Resolver: "192.0.2.76",
			ResolverPort: 53, IsValid: true, UploadMTUBytes: 220, DownloadMTUBytes: 1200,
			MTUResolveTime: 50 * time.Millisecond,
		},
	}
	c.connectionsByKey = map[string]int{"resolver-a": 0, "resolver-b": 1}
	c.balancer = NewBalancer(BalancingRoundRobinDefault)
	c.balancer.SetConnections([]*Connection{&c.connections[0], &c.connections[1]})
	now := time.Now()
	c.noteResolverTransportProbe("resolver-a", transportTCP, mtuConnectionProbeResult{
		UploadBytes: 220, DownloadBytes: 1200, ResolveTime: 300 * time.Millisecond,
	}, true, now)
	c.noteResolverTransportProbe("resolver-b", transportUDP, mtuConnectionProbeResult{
		UploadBytes: 220, DownloadBytes: 1200, ResolveTime: 50 * time.Millisecond,
	}, true, now)

	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.75"), Port: 53}
	query, err := DnsParser.BuildTXTQuestionPacket("payload.tunnel.example", Enums.DNS_RECORD_TYPE_TXT, 4096)
	if err != nil {
		t.Fatal(err)
	}
	c.trackResolverFrameOver(encodedOutboundDatagram{
		addr: addr, serverKey: "resolver-a", packet: query,
		priority: Enums.PacketPriorityNormal, transport: transportUDP,
		packetType: Enums.PACKET_STREAM_DATA, payloadSize: 80,
	}, "udp-local", transportUDP, now)
	c.noteInjectedResolverNoise(hostileDNSResponse(query, Enums.DNSR_CODE_NAME_ERROR), addr, "udp-local", transportUDP)

	task := <-c.encodedTXChannel
	replay := task.frames[0]
	if replay.serverKey != "resolver-b" || replay.transport != transportUDP {
		t.Fatalf("replay selected %s/%s, want fastest resolver-b/udp", replay.serverKey, replay.transport)
	}
}
