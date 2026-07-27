package client

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	Enums "cottendns-go/internal/enums"
	VpnProto "cottendns-go/internal/vpnproto"
)

const (
	transportFailureSwitchThreshold = 2
	transportSpeedSampleThreshold   = 3
	transportSpeedSwitchRatio       = 1.20
	transportProbeInterval          = 2 * time.Second
	transportSwitchCooldown         = 3 * time.Second
	transportPoisonMemory           = 2 * time.Minute
)

type resolverPathScore struct {
	rttEWMA       time.Duration
	successes     uint32
	failures      uint32
	failureStreak uint8
	poisonEvents  uint32
	lastPoison    time.Time
	probed        bool
	viable        bool
	uploadMTU     int
	downloadMTU   int
	uploadLoss    float64
	downloadLoss  float64
	lastSuccess   time.Time
	lastFailure   time.Time
}

type resolverTransportState struct {
	preferred          resolverTransport
	paths              [4]resolverPathScore
	lastProbe          time.Time
	lastSwitch         time.Time
	lastBackgroundScan time.Time
	probeCursor        int
	backgroundCursor   int
}

type resolverTransportDecision struct {
	primary   resolverTransport
	secondary resolverTransport
	hedge     bool
}

type resolverRuntimePath struct {
	connection Connection
	transport  resolverTransport
	score      float64
	hedge      bool
}

func validResolverTransport(transport resolverTransport) bool {
	return transport >= transportUDP && transport <= transportDoH
}

func (c *Client) resolverTransportPolicyName(serverKey string) string {
	if c == nil {
		return "udp"
	}
	conn, hasConnection := c.GetConnectionByKey(serverKey)
	candidates := []string{serverKey}
	if hasConnection {
		candidates = append(candidates, conn.ResolverLabel, conn.Resolver)
		if host, _, err := net.SplitHostPort(conn.ResolverLabel); err == nil {
			candidates = append(candidates, host)
		}
	}
	for _, candidate := range candidates {
		if policy, ok := c.cfg.ResolverTransportPaths[strings.TrimSpace(candidate)]; ok {
			return policy
		}
	}
	policy := strings.ToLower(strings.TrimSpace(c.cfg.ResolverTransport))
	if policy == "" {
		return "auto"
	}
	return policy
}

func (c *Client) resolverTransportCandidates(serverKey string) []resolverTransport {
	return resolverTransportChain(c.resolverTransportPolicyName(serverKey))
}

func (c *Client) perResolverAutoTransport() bool {
	if c == nil {
		return false
	}
	for _, conn := range c.connections {
		if len(c.resolverTransportCandidates(conn.Key)) > 1 {
			return true
		}
	}
	return len(resolverTransportChain(c.cfg.ResolverTransport)) > 1
}

func (c *Client) resolverTransportPolicyKey(serverKey string) string {
	if conn, ok := c.GetConnectionByKey(serverKey); ok && conn.ResolverLabel != "" {
		return conn.ResolverLabel
	}
	return serverKey
}

func (c *Client) resolverTransportStateLocked(serverKey string) *resolverTransportState {
	serverKey = c.resolverTransportPolicyKey(serverKey)
	if c.resolverTransports == nil {
		c.resolverTransports = make(map[string]*resolverTransportState)
	}
	state := c.resolverTransports[serverKey]
	if state == nil {
		candidates := c.resolverTransportCandidates(serverKey)
		preferred := c.activeTransport()
		if len(candidates) > 0 {
			preferred = candidates[0]
		}
		state = &resolverTransportState{preferred: preferred}
		c.resolverTransports[serverKey] = state
	}
	return state
}

func pathScoreFor(state *resolverTransportState, transport resolverTransport) *resolverPathScore {
	if state == nil || !validResolverTransport(transport) {
		return nil
	}
	return &state.paths[int(transport)]
}

func (c *Client) pathSupportsSession(score *resolverPathScore) bool {
	if score == nil {
		return false
	}
	// Cached/log-based startup may not have measured the alternate yet. Keep it
	// available for a control hedge or emergency failover; the first result will
	// immediately replace this optimistic state. A path that was actually
	// probed and failed is never selected.
	if !score.probed {
		return true
	}
	if !score.viable {
		return false
	}
	if c.syncedUploadMTU > 0 && score.uploadMTU > 0 && score.uploadMTU < c.syncedUploadMTU {
		return false
	}
	if c.syncedDownloadMTU > 0 && score.downloadMTU > 0 && score.downloadMTU < c.syncedDownloadMTU {
		return false
	}
	return true
}

// requiredUploadProbeMTU translates a runtime packet into the payload size used
// by MTU_UP probes. Probe results describe the MTU request payload, while native
// packet headers vary slightly by type, so compare equivalent raw sizes.
func requiredUploadProbeMTU(packetType uint8, payloadSize int) int {
	if payloadSize < 0 {
		payloadSize = 0
	}
	required := payloadSize + VpnProto.HeaderRawSize(packetType) - VpnProto.HeaderRawSize(Enums.PACKET_MTU_UP_REQ)
	if required < 1 {
		return 1
	}
	return required
}

func pathSupportsPacket(score *resolverPathScore, packetType uint8, payloadSize int) bool {
	if score == nil {
		return false
	}
	if !score.probed {
		return true
	}
	if !score.viable {
		return false
	}
	required := requiredUploadProbeMTU(packetType, payloadSize)
	return score.uploadMTU <= 0 || score.uploadMTU >= required
}

func pathEstimatedGoodput(score *resolverPathScore) float64 {
	if score == nil || !score.probed || !score.viable {
		return 0
	}
	mtu := score.downloadMTU
	if mtu <= 0 {
		mtu = 1
	}
	delivery := 1 - score.downloadLoss
	if delivery < 0.01 {
		delivery = 0.01
	}
	rttMillis := float64(score.rttEWMA) / float64(time.Millisecond)
	if rttMillis < 1 {
		rttMillis = 1
	}
	return float64(mtu) * delivery / rttMillis
}

func pathEstimatedGoodputForPacket(score *resolverPathScore, packetType uint8) float64 {
	if score == nil || !score.probed || !score.viable {
		return 0
	}
	mtu, loss := score.uploadMTU, score.uploadLoss
	switch packetType {
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_DATA_NACK, Enums.PACKET_PING:
		mtu, loss = score.downloadMTU, score.downloadLoss
	}
	if mtu <= 0 {
		mtu = 1
	}
	delivery := 1 - loss
	if delivery < 0.01 {
		delivery = 0.01
	}
	rttMillis := float64(score.rttEWMA) / float64(time.Millisecond)
	if rttMillis < 1 {
		rttMillis = 1
	}
	value := float64(mtu) * delivery / rttMillis
	if score.failureStreak > 0 {
		value /= 1 + float64(score.failureStreak*2)
	}
	return value
}

func fallbackConnectionPathScore(conn Connection, packetType uint8) float64 {
	mtu, loss := conn.UploadMTUBytes, conn.UploadMTULoss
	switch packetType {
	case Enums.PACKET_STREAM_DATA_ACK, Enums.PACKET_STREAM_DATA_NACK, Enums.PACKET_PING:
		mtu, loss = conn.DownloadMTUBytes, conn.DownloadMTULoss
	}
	if mtu <= 0 {
		mtu = 1
	}
	delivery := 1 - loss
	if delivery < 0.01 {
		delivery = 0.01
	}
	rttMillis := float64(conn.MTUResolveTime) / float64(time.Millisecond)
	if rttMillis < 1 {
		rttMillis = 1
	}
	return float64(mtu) * delivery / rttMillis
}

// bestPacketTransportLocked selects a resolver's best transport for the actual
// packet size. Unlike session-level selection, this deliberately permits a
// measured narrow path when the current packet fits it.
func (c *Client) bestPacketTransportLocked(
	serverKey string,
	state *resolverTransportState,
	packetType uint8,
	payloadSize int,
) (resolverTransport, float64, bool) {
	var (
		best      resolverTransport
		bestScore = -1.0
		found     bool
	)
	for _, transport := range c.resolverTransportCandidates(serverKey) {
		path := pathScoreFor(state, transport)
		if !path.probed &&
			(packetType == Enums.PACKET_STREAM_DATA || packetType == Enums.PACKET_STREAM_RESEND) {
			// Never infer bulk capacity on an unmeasured transport. Startup's
			// emergency legacy fallback remains available when no measured path
			// exists, while normal joint routing keeps bulk off unknown MTUs.
			continue
		}
		if !pathSupportsPacket(path, packetType, payloadSize) {
			continue
		}
		value := pathEstimatedGoodputForPacket(path, packetType)
		// Unmeasured configured paths remain emergency candidates but never
		// outrank a measured healthy path.
		if !path.probed {
			value = 0.0001
		}
		if !found || value > bestScore {
			best, bestScore, found = transport, value, true
		}
	}
	return best, bestScore, found
}

// selectJointRuntimePaths scores resolver and transport together. Backup
// resolvers participate whenever the concrete packet fits their measured MTU,
// which converts narrow paths into useful capacity without lowering the global
// session MTU or penalizing bulk traffic on clean paths.
func (c *Client) selectJointRuntimePaths(
	packetType uint8,
	streamID uint16,
	payloadSize int,
	count int,
	now time.Time,
) []resolverRuntimePath {
	if c == nil || c.balancer == nil {
		return nil
	}
	if count < 1 {
		count = 1
	}

	connections := c.balancer.AllValidConnectionsIncludingBackup()
	eligibleConnections := make([]Connection, 0, len(connections))
	for _, conn := range connections {
		if conn.IsValid && conn.Key != "" && !c.isRuntimeDisabledResolver(conn.Key) {
			eligibleConnections = append(eligibleConnections, conn)
		}
	}
	paths := make([]resolverRuntimePath, 0, len(eligibleConnections))

	preferredKey := ""
	if streamID != 0 &&
		(packetType == Enums.PACKET_STREAM_DATA || packetType == Enums.PACKET_STREAM_RESEND) {
		if stream, ok := c.getStream(streamID); ok && stream != nil {
			stream.resolverMu.Lock()
			preferredKey = stream.PreferredServerKey
			stream.resolverMu.Unlock()
		}
	}

	c.resolverTransportMu.Lock()
	for _, conn := range eligibleConnections {
		state := c.resolverTransportStateLocked(conn.Key)
		transport, score, ok := c.bestPacketTransportLocked(conn.Key, state, packetType, payloadSize)
		if !ok {
			continue
		}
		if score <= 0.0001 {
			score = fallbackConnectionPathScore(conn, packetType)
		}
		if conn.Key == preferredKey {
			// Mild stickiness prevents reordering for statistically equivalent
			// paths while still allowing a meaningfully faster path to win.
			score *= 1.10
		}
		paths = append(paths, resolverRuntimePath{
			connection: conn,
			transport:  transport,
			score:      score,
		})
	}
	c.resolverTransportMu.Unlock()

	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].score == paths[j].score {
			return paths[i].connection.Key < paths[j].connection.Key
		}
		return paths[i].score > paths[j].score
	})
	if len(paths) == 0 {
		return nil
	}

	selected := make([]resolverRuntimePath, 0, count+1)
	seenResolvers := make(map[string]struct{}, count)
	seenDomains := make(map[string]struct{}, count)
	appendPath := func(path resolverRuntimePath) bool {
		if _, exists := seenResolvers[path.connection.Key]; exists {
			return false
		}
		selected = append(selected, path)
		seenResolvers[path.connection.Key] = struct{}{}
		seenDomains[path.connection.Domain] = struct{}{}
		return true
	}

	if c.dupPreferDistinctDomains && count > 1 {
		for _, path := range paths {
			if len(selected) >= count {
				break
			}
			if _, duplicateDomain := seenDomains[path.connection.Domain]; duplicateDomain {
				continue
			}
			appendPath(path)
		}
	}
	for _, path := range paths {
		if len(selected) >= count {
			break
		}
		appendPath(path)
	}

	// Sparse control traffic can explore one alternate transport on the same
	// resolver. Bulk packets never hedge, so exploration cannot cap throughput.
	if len(selected) > 0 && Enums.DefaultPacketPriority(packetType) <= Enums.PacketPriorityHigh {
		primary := selected[0]
		c.resolverTransportMu.Lock()
		state := c.resolverTransportStateLocked(primary.connection.Key)
		if state.lastProbe.IsZero() || now.Sub(state.lastProbe) >= transportProbeInterval {
			for _, alternate := range c.resolverTransportCandidates(primary.connection.Key) {
				if alternate == primary.transport ||
					!pathSupportsPacket(pathScoreFor(state, alternate), packetType, payloadSize) {
					continue
				}
				selected = append(selected, resolverRuntimePath{
					connection: primary.connection,
					transport:  alternate,
					score:      primary.score,
					hedge:      true,
				})
				state.lastProbe = now
				break
			}
		}
		c.resolverTransportMu.Unlock()
	}
	return selected
}

func (c *Client) alternateResolverTransportForPacket(
	serverKey string,
	exclude resolverTransport,
	packetType uint8,
	payloadSize int,
) (resolverTransport, bool) {
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	var (
		best      resolverTransport
		bestScore = -1.0
		found     bool
	)
	for _, transport := range c.resolverTransportCandidates(serverKey) {
		if transport == exclude {
			continue
		}
		score := pathScoreFor(state, transport)
		if !pathSupportsPacket(score, packetType, payloadSize) {
			continue
		}
		value := pathEstimatedGoodputForPacket(score, packetType)
		if !score.probed {
			value = 0.0001
		}
		if !found || value > bestScore {
			best, bestScore, found = transport, value, true
		}
	}
	return best, found
}

func (c *Client) bestResolverTransportLocked(serverKey string, state *resolverTransportState) resolverTransport {
	candidates := c.resolverTransportCandidates(serverKey)
	if len(candidates) == 0 {
		return c.activeTransport()
	}
	best := candidates[0]
	bestScore := -1.0
	for _, transport := range candidates {
		score := pathScoreFor(state, transport)
		if !c.pathSupportsSession(score) {
			continue
		}
		value := pathEstimatedGoodput(score)
		if score.failureStreak >= transportFailureSwitchThreshold {
			value *= 0.05
		}
		if value > bestScore {
			best, bestScore = transport, value
		}
	}
	if bestScore < 0 {
		for _, transport := range candidates {
			if transport == state.preferred {
				return transport
			}
		}
		return candidates[0]
	}
	return best
}

func (c *Client) chooseResolverTransport(serverKey string, priority int, now time.Time) resolverTransportDecision {
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	candidates := c.resolverTransportCandidates(serverKey)
	if len(candidates) <= 1 {
		if len(candidates) == 1 {
			state.preferred = candidates[0]
		}
		return resolverTransportDecision{primary: state.preferred}
	}

	best := c.bestResolverTransportLocked(serverKey, state)
	if best != state.preferred && now.Sub(state.lastSwitch) >= transportSwitchCooldown {
		state.preferred = best
		state.lastSwitch = now
	}
	decision := resolverTransportDecision{primary: state.preferred}

	// Sparse control/setup traffic samples one alternate path. Bulk data never
	// gets transport-duplicated, so path learning cannot halve useful goodput.
	if priority <= Enums.PacketPriorityHigh &&
		(state.lastProbe.IsZero() || now.Sub(state.lastProbe) >= transportProbeInterval) {
		for attempts := 0; attempts < len(candidates); attempts++ {
			state.probeCursor = (state.probeCursor + 1) % len(candidates)
			alternate := candidates[state.probeCursor]
			if alternate == decision.primary || !c.pathSupportsSession(pathScoreFor(state, alternate)) {
				continue
			}
			decision.secondary = alternate
			decision.hedge = true
			state.lastProbe = now
			break
		}
	}
	return decision
}

func updatePathRTT(score *resolverPathScore, rtt time.Duration) {
	if score == nil {
		return
	}
	if rtt < 0 {
		rtt = 0
	}
	if score.rttEWMA == 0 {
		score.rttEWMA = rtt
		return
	}
	score.rttEWMA = (score.rttEWMA*7 + rtt) / 8
}

func (c *Client) noteResolverTransportProbe(
	serverKey string,
	transport resolverTransport,
	result mtuConnectionProbeResult,
	ok bool,
	now time.Time,
) {
	if c == nil || serverKey == "" || !validResolverTransport(transport) {
		return
	}
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	score := pathScoreFor(state, transport)
	score.probed = true
	score.viable = ok
	if ok {
		score.uploadMTU = result.UploadBytes
		score.downloadMTU = result.DownloadBytes
		score.uploadLoss = result.UploadLoss
		score.downloadLoss = result.DownloadLoss
		score.failureStreak = 0
		score.lastSuccess = now
		updatePathRTT(score, result.ResolveTime)
	} else {
		score.lastFailure = now
	}
	best := c.bestResolverTransportLocked(serverKey, state)
	if best != state.preferred {
		state.preferred = best
		state.lastSwitch = now
	}
}

func (c *Client) noteResolverTransportSuccess(serverKey string, transport resolverTransport, rtt time.Duration, now time.Time) {
	if c == nil || serverKey == "" || !validResolverTransport(transport) {
		return
	}
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	score := pathScoreFor(state, transport)
	score.probed = true
	score.viable = true
	if score.uploadMTU == 0 {
		score.uploadMTU = max(1, c.syncedUploadMTU)
	}
	if score.downloadMTU == 0 {
		score.downloadMTU = max(1, c.syncedDownloadMTU)
	}
	score.successes++
	score.failureStreak = 0
	score.lastSuccess = now
	updatePathRTT(score, rtt)

	if now.Sub(state.lastSwitch) < transportSwitchCooldown {
		return
	}
	best := c.bestResolverTransportLocked(serverKey, state)
	current := pathScoreFor(state, state.preferred)
	better := pathScoreFor(state, best)
	if best != state.preferred &&
		better != nil && better.successes >= transportSpeedSampleThreshold &&
		(current == nil || current.successes >= transportSpeedSampleThreshold) &&
		pathEstimatedGoodput(better) > pathEstimatedGoodput(current)*transportSpeedSwitchRatio {
		state.preferred = best
		state.lastSwitch = now
	}
}

func (c *Client) noteResolverTransportFailure(serverKey string, transport resolverTransport, now time.Time) {
	if c == nil || serverKey == "" || !validResolverTransport(transport) {
		return
	}
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	score := pathScoreFor(state, transport)
	score.failures++
	score.lastFailure = now
	if score.failureStreak < 255 {
		score.failureStreak++
	}
	requiredFailures := uint8(transportFailureSwitchThreshold)
	if !score.lastPoison.IsZero() {
		poisonAge := now.Sub(score.lastPoison)
		// Timeout observations carry their scheduled deadline, which can be a
		// few milliseconds earlier than the wall-clock poison arrival processed
		// beside it. Treat that ordering as simultaneous, not stale/future.
		if poisonAge < 0 {
			poisonAge = 0
		}
		if poisonAge <= transportPoisonMemory {
			requiredFailures = 1
		}
	}
	if state.preferred != transport || score.failureStreak < requiredFailures ||
		now.Sub(state.lastSwitch) < transportSwitchCooldown {
		return
	}
	best := c.bestResolverTransportLocked(serverKey, state)
	if best == transport {
		for _, candidate := range c.resolverTransportCandidates(serverKey) {
			if candidate != transport && c.pathSupportsSession(pathScoreFor(state, candidate)) {
				best = candidate
				break
			}
		}
	}
	if best != transport && c.pathSupportsSession(pathScoreFor(state, best)) {
		state.preferred = best
		state.lastSwitch = now
	}
}

// noteResolverTransportHardFailure handles an explicit path-level rejection
// such as UDP truncation. Waiting for a second timeout wastes an entire ARQ RTO,
// so an eligible alternate becomes preferred immediately.
func (c *Client) noteResolverTransportHardFailure(serverKey string, transport resolverTransport, now time.Time) {
	if c == nil || serverKey == "" || !validResolverTransport(transport) {
		return
	}
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	score := pathScoreFor(state, transport)
	score.failures++
	score.lastFailure = now
	if score.failureStreak < transportFailureSwitchThreshold {
		score.failureStreak = transportFailureSwitchThreshold
	}
	if state.preferred != transport {
		return
	}
	for _, candidate := range c.resolverTransportCandidates(serverKey) {
		if candidate == transport {
			continue
		}
		alternate := pathScoreFor(state, candidate)
		if !alternate.probed || alternate.viable {
			state.preferred = candidate
			state.lastSwitch = now
			state.lastProbe = time.Time{}
			return
		}
	}
}
func (c *Client) noteResolverTransportPoison(serverKey string, transport resolverTransport) {
	if c == nil || serverKey == "" || !validResolverTransport(transport) {
		return
	}
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	score := pathScoreFor(state, transport)
	score.poisonEvents++
	score.lastPoison = c.now()
	// Poison alone is not failure: if the authenticated answer still wins
	// quickly, the poisoned environment remains usable. Force a prompt alternate
	// comparison; timeout/RTT decides whether to leave the path.
	state.lastProbe = time.Time{}
}

func (c *Client) preferredResolverTransport(serverKey string) resolverTransport {
	return c.chooseResolverTransport(serverKey, Enums.PacketPriorityNormal, c.now()).primary
}

func (c *Client) orderedResolverTransports(serverKey string) []resolverTransport {
	c.resolverTransportMu.Lock()
	defer c.resolverTransportMu.Unlock()
	state := c.resolverTransportStateLocked(serverKey)
	candidates := c.resolverTransportCandidates(serverKey)
	out := make([]resolverTransport, 0, len(candidates))
	if validResolverTransport(state.preferred) {
		out = append(out, state.preferred)
	}
	for _, transport := range candidates {
		if transport != state.preferred {
			out = append(out, transport)
		}
	}
	return out
}

func (c *Client) runtimeTransportsNeeded() map[resolverTransport]bool {
	needed := make(map[resolverTransport]bool)
	if c == nil || len(c.connections) == 0 {
		for _, transport := range resolverTransportChain(c.cfg.ResolverTransport) {
			needed[transport] = true
		}
		return needed
	}
	for _, conn := range c.connections {
		for _, transport := range c.resolverTransportCandidates(conn.Key) {
			needed[transport] = true
		}
	}
	return needed
}

func (c *Client) transportBackgroundScanInterval() time.Duration {
	if c == nil || c.cfg.ResolverTransportBackgroundScanIntervalSec <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.cfg.ResolverTransportBackgroundScanIntervalSec * float64(time.Second))
}

func (c *Client) resolverTransportSummary() string {
	if c == nil {
		return "unknown"
	}
	if !c.perResolverAutoTransport() {
		return c.activeTransport().String()
	}
	var counts [4]int
	c.resolverTransportMu.Lock()
	for _, conn := range c.connections {
		if !conn.IsValid {
			continue
		}
		transport := c.resolverTransportStateLocked(conn.Key).preferred
		if validResolverTransport(transport) {
			counts[int(transport)]++
		}
	}
	c.resolverTransportMu.Unlock()
	return fmt.Sprintf("adaptive UDP=%d TCP=%d DoT=%d DoH=%d",
		counts[transportUDP], counts[transportTCP], counts[transportDoT], counts[transportDoH])
}
