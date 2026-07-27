package client

import (
	"encoding/binary"
	"net"
	"sort"
	"time"

	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
)

const (
	resolverPendingSoftCap   = 8192
	resolverPendingHardCap   = 12288
	resolverPendingTargetCap = 8192

	// injectionLogInterval throttles the "ignored forged NXDOMAIN" warning so a
	// heavy injection campaign cannot flood the log.
	injectionLogInterval = 10 * time.Second
)

// rcodeIsInjectedNoise reports whether a non-zero DNS RCODE on a tunnel response
// should be treated as on-path injection noise rather than a genuine resolver
// failure (see RESOLVER_IGNORE_INJECTED_NXDOMAIN). NXDOMAIN is the reliable tell:
// the authoritative tunnel server never returns it for a valid tunnel query, and
// a genuinely overloaded recursor returns SERVFAIL/REFUSED, not NXDOMAIN — so a
// NXDOMAIN carrying no tunnel payload is almost certainly a forged answer raced
// in by an on-path censor. Genuine unreachability is still caught by the pending
// sample timing out, which injection cannot forge.
func (c *Client) rcodeIsInjectedNoise(rcode uint8) bool {
	if c == nil || !c.cfg.ResolverIgnoreInjectedNXDOMAIN {
		return false
	}
	return rcode == Enums.DNSR_CODE_NAME_ERROR
}

// noteInjectedResolverNoise records that a forged NXDOMAIN was ignored. The
// caller deliberately does NOT consume the pending query sample, so the genuine
// answer can still be scored as a success (or the sample times out if the
// resolver is truly unreachable). A throttled warning lets the operator see that
// DNS poisoning is happening and being absorbed.
func (c *Client) noteInjectedResolverNoise(packet []byte, addr *net.UDPAddr, localAddr string, transport resolverTransport) {
	if c == nil {
		return
	}
	total := c.injectedNXDOMAINCount.Add(1)
	if len(packet) >= 2 && addr != nil {
		fingerprint := dnsQuestionFingerprint(packet)
		key := resolverSampleKey{
			resolverAddr:        addr.String(),
			localAddr:           localAddr,
			dnsID:               binary.BigEndian.Uint16(packet[:2]),
			transport:           transport,
			questionFingerprint: fingerprint,
		}
		c.resolverStatsMu.RLock()
		actualKey, sample, ok := c.resolverSampleLocked(key)
		c.resolverStatsMu.RUnlock()
		if ok && (sample.questionFingerprint == 0 || sample.questionFingerprint == fingerprint) {
			c.noteResolverTransportPoison(sample.serverKey, transport)
			c.replayPendingResolverSample(actualKey, poisonReplayMaxDepth)
		}
	}
	now := time.Now().UnixNano()
	last := c.lastInjectionLogUnix.Load()
	if now-last < injectionLogInterval.Nanoseconds() {
		return
	}
	if !c.lastInjectionLogUnix.CompareAndSwap(last, now) {
		return
	}
	if c.log != nil {
		c.log.Warnf(
			"\U0001F9EA <yellow>Ignored forged NXDOMAIN (DNS injection)</yellow> <magenta>|</magenta> <blue>Total</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Resolver</blue>: <cyan>%v</cyan> <magenta>|</magenta> <green>resolver kept active</green>",
			total,
			addr,
		)
	}
}

// validateInboundQuestion rejects same-ID responses whose question section does
// not match the outstanding query. TXID-only matching is insufficient in an
// actively poisoned network because an injector can observe or guess the ID.
// The pending sample remains intact so the authentic response can still win.
func (c *Client) validateInboundQuestion(packet []byte, addr *net.UDPAddr, localAddr string, transport resolverTransport) bool {
	valid, _ := c.validateInboundQuestionFingerprint(packet, addr, localAddr, transport)
	return valid
}

func (c *Client) validateInboundQuestionFingerprint(
	packet []byte,
	addr *net.UDPAddr,
	localAddr string,
	transport resolverTransport,
) (bool, uint64) {
	if c == nil || len(packet) < 2 || addr == nil {
		return false, 0
	}
	fingerprint := dnsQuestionFingerprint(packet)
	key := resolverSampleKey{
		resolverAddr:        addr.String(),
		localAddr:           localAddr,
		dnsID:               binary.BigEndian.Uint16(packet[:2]),
		transport:           transport,
		questionFingerprint: fingerprint,
	}
	c.resolverStatsMu.RLock()
	actualKey, sample, ok := c.resolverSampleLocked(key)
	c.resolverStatsMu.RUnlock()
	if !ok || sample.questionFingerprint == 0 {
		return true, fingerprint
	}
	if fingerprint == sample.questionFingerprint {
		return true, fingerprint
	}

	total := c.resolverHijackCount.Add(1)
	c.noteResolverTransportPoison(sample.serverKey, transport)
	c.replayPendingResolverSample(actualKey, poisonReplayMaxDepth)
	now := time.Now().UnixNano()
	last := c.lastHijackLogUnix.Load()
	if now-last >= injectionLogInterval.Nanoseconds() &&
		c.lastHijackLogUnix.CompareAndSwap(last, now) &&
		c.log != nil {
		c.log.Warnf(
			"\U0001F6E1 <yellow>Ignored mismatched DNS response (resolver hijack/injection)</yellow> <magenta>|</magenta> <blue>Total</blue>: <cyan>%d</cyan> <magenta>|</magenta> <blue>Resolver</blue>: <cyan>%v</cyan>",
			total,
			addr,
		)
	}
	return false, fingerprint
}

type resolverSampleKey struct {
	resolverAddr        string
	localAddr           string
	dnsID               uint16
	transport           resolverTransport
	questionFingerprint uint64
}

type resolverCompletedKey struct {
	dnsID               uint16
	questionFingerprint uint64
}

type resolverSample struct {
	serverKey           string
	transport           resolverTransport
	questionFingerprint uint64
	sentAt              time.Time
	timeoutAt           time.Time
	timedOut            bool
	timedOutAt          time.Time
	evictAfter          time.Time
	packet              []byte
	packetType          uint8
	payloadSize         int
	priority            int
	replayDepth         uint8
	replayTriggered     bool
	mayHaveSibling      bool
}

type resolverTimeoutObservation struct {
	serverKey string
	transport resolverTransport
	at        time.Time
	key       resolverSampleKey
}

func (c *Client) resolverSampleTTL() time.Duration {
	if c == nil {
		return 15 * time.Second
	}

	ttl := c.tunnelPacketTimeout * 3
	if ttl < 10*time.Second {
		ttl = 10 * time.Second
	}
	if ttl > 45*time.Second {
		ttl = 45 * time.Second
	}
	return ttl
}

func (c *Client) noteResolverSend(serverKey string) {
	if c == nil || serverKey == "" || c.balancer == nil {
		return
	}
	c.balancer.ReportSend(serverKey)
}

func (c *Client) noteResolverSuccess(serverKey string, rtt time.Duration) {
	if c == nil || serverKey == "" || c.balancer == nil {
		return
	}
	if rtt < 0 {
		rtt = 0
	}
	c.balancer.ReportSuccess(serverKey, rtt)
	c.recordResolverHealthEvent(serverKey, true, c.now())
}

func (c *Client) trackResolverSend(packet []byte, resolverAddr string, localAddr string, serverKey string, sentAt time.Time) {
	c.trackResolverSendOver(packet, resolverAddr, localAddr, serverKey, c.activeTransport(), sentAt)
}

func (c *Client) trackResolverSendOver(packet []byte, resolverAddr string, localAddr string, serverKey string, transport resolverTransport, sentAt time.Time) {
	c.trackResolverSendMetadata(packet, resolverAddr, localAddr, serverKey, transport, sentAt, 0, 0, 0, 0, false, false)
}

func (c *Client) trackResolverFrameOver(frame encodedOutboundDatagram, localAddr string, transport resolverTransport, sentAt time.Time) {
	if frame.addr == nil {
		return
	}
	c.trackResolverSendMetadata(
		frame.packet,
		frame.addr.String(),
		localAddr,
		frame.serverKey,
		transport,
		sentAt,
		frame.packetType,
		frame.payloadSize,
		frame.priority,
		frame.replayDepth,
		frame.mayHaveSibling,
		true,
	)
}

func (c *Client) trackResolverSendMetadata(
	packet []byte,
	resolverAddr string,
	localAddr string,
	serverKey string,
	transport resolverTransport,
	sentAt time.Time,
	packetType uint8,
	payloadSize int,
	priority int,
	replayDepth uint8,
	mayHaveSibling bool,
	keepPacket bool,
) {
	if c == nil || len(packet) < 2 || resolverAddr == "" || serverKey == "" {
		return
	}

	fingerprint := dnsQuestionFingerprint(packet)
	key := resolverSampleKey{
		resolverAddr:        resolverAddr,
		localAddr:           localAddr,
		dnsID:               binary.BigEndian.Uint16(packet[:2]),
		transport:           transport,
		questionFingerprint: fingerprint,
	}
	timeoutAt := sentAt.Add(c.resolverPathRequestTimeout(serverKey, transport))

	var timeoutObservations []resolverTimeoutObservation
	c.resolverStatsMu.Lock()
	if len(c.resolverPending) >= resolverPendingSoftCap {
		timeoutObservations = c.pruneResolverSamplesLocked(sentAt)
		if overflow := len(c.resolverPending) - resolverPendingHardCap; overflow >= 0 {
			c.evictResolverPendingLocked(overflow + 1)
		}
	}
	sample := resolverSample{
		serverKey:           serverKey,
		transport:           transport,
		questionFingerprint: fingerprint,
		sentAt:              sentAt,
		timeoutAt:           timeoutAt,
		packetType:          packetType,
		payloadSize:         payloadSize,
		priority:            priority,
		replayDepth:         replayDepth,
		mayHaveSibling:      mayHaveSibling,
	}
	if keepPacket {
		// Runtime DNS frames are immutable after encoding. Retaining the slice
		// keeps its backing array alive for replay without adding one allocation
		// and full packet copy to every foreground send.
		sample.packet = packet
	}
	c.resolverPending[key] = sample
	c.resolverStatsMu.Unlock()

	for _, observation := range timeoutObservations {
		c.noteResolverTimeout(observation.serverKey, observation.at)
		c.noteResolverTransportFailure(observation.serverKey, observation.transport, observation.at)
		c.replayPendingResolverSample(observation.key, failureReplayMaxDepth)
	}
	c.noteResolverSend(serverKey)
}

func (c *Client) trackResolverSuccess(packet []byte, addr *net.UDPAddr, localAddr string, receivedAt time.Time) bool {
	return c.trackResolverSuccessOver(packet, addr, localAddr, c.activeTransport(), receivedAt)
}

func (c *Client) trackResolverSuccessOver(packet []byte, addr *net.UDPAddr, localAddr string, transport resolverTransport, receivedAt time.Time) bool {
	return c.trackResolverSuccessOverFingerprint(
		packet, addr, localAddr, transport, receivedAt, dnsQuestionFingerprint(packet),
	)
}

func (c *Client) trackResolverSuccessOverFingerprint(
	packet []byte,
	addr *net.UDPAddr,
	localAddr string,
	transport resolverTransport,
	receivedAt time.Time,
	fingerprint uint64,
) bool {
	if c == nil || len(packet) < 2 || addr == nil {
		return false
	}

	key := resolverSampleKey{
		resolverAddr:        addr.String(),
		localAddr:           localAddr,
		dnsID:               binary.BigEndian.Uint16(packet[:2]),
		transport:           transport,
		questionFingerprint: fingerprint,
	}
	completedKey := resolverCompletedKey{
		dnsID:               key.dnsID,
		questionFingerprint: key.questionFingerprint,
	}

	c.resolverStatsMu.Lock()
	if expiresAt, completed := c.resolverCompleted[completedKey]; completed {
		if expiresAt.After(receivedAt) {
			c.resolverStatsMu.Unlock()
			return false
		}
		delete(c.resolverCompleted, completedKey)
	}
	actualKey, sample, ok := c.resolverSampleLocked(key)
	if ok && sample.questionFingerprint != 0 && sample.questionFingerprint != fingerprint {
		ok = false
	}
	if ok {
		delete(c.resolverPending, actualKey)
		// A hedge or replay may use another socket, resolver, or transport. Claim
		// every logically identical query when the first authenticated answer
		// wins, so a slower copy cannot be dispatched or counted as a timeout.
		if sample.mayHaveSibling || sample.replayTriggered || sample.replayDepth > 0 {
			for siblingKey, sibling := range c.resolverPending {
				sameLogicalQuery := siblingKey.dnsID == key.dnsID &&
					sample.questionFingerprint != 0 &&
					sibling.questionFingerprint == sample.questionFingerprint
				legacySibling := sample.questionFingerprint == 0 &&
					siblingKey.resolverAddr == key.resolverAddr &&
					sibling.serverKey == sample.serverKey
				if sameLogicalQuery || legacySibling {
					delete(c.resolverPending, siblingKey)
				}
			}
		}
		if completedKey.questionFingerprint != 0 {
			if c.resolverCompleted == nil {
				c.resolverCompleted = make(map[resolverCompletedKey]time.Time)
			}
			if len(c.resolverCompleted) >= resolverPendingHardCap {
				for oldKey := range c.resolverCompleted {
					delete(c.resolverCompleted, oldKey)
					break
				}
			}
			c.resolverCompleted[completedKey] = receivedAt.Add(c.resolverSampleTTL())
		}
	}
	c.resolverStatsMu.Unlock()

	if !ok || sample.serverKey == "" {
		return false
	}

	// Credit the carrier only after atomically claiming a real outstanding
	// sample. handleInboundPacket calls this path only after decoding a tunnel
	// frame, so empty/NODATA replies and duplicated DNS answers cannot inflate a
	// carrier's delivery rate.
	if qType, qTypeOK := DnsParser.FirstQuestionQType(packet); qTypeOK && c.carrier != nil {
		c.carrier.recordSuccessForPath(sample.serverKey, qType)
	}

	if sample.timedOut && !sample.timedOutAt.IsZero() {
		c.retractResolverTimeoutEvent(sample.serverKey, sample.timedOutAt, receivedAt)
	}

	c.recordTunnelResponse(receivedAt)
	c.noteResolverSuccess(sample.serverKey, receivedAt.Sub(sample.sentAt))
	c.noteResolverTransportSuccess(sample.serverKey, sample.transport, receivedAt.Sub(sample.sentAt), receivedAt)
	return true
}

func (c *Client) resolverReplayCompleted(frame encodedOutboundDatagram, now time.Time) bool {
	if c == nil || frame.replayDepth == 0 || len(frame.packet) < 2 {
		return false
	}
	key := resolverCompletedKey{
		dnsID:               binary.BigEndian.Uint16(frame.packet[:2]),
		questionFingerprint: dnsQuestionFingerprint(frame.packet),
	}
	if key.questionFingerprint == 0 {
		return false
	}
	c.resolverStatsMu.Lock()
	expiresAt, completed := c.resolverCompleted[key]
	if completed && !expiresAt.After(now) {
		delete(c.resolverCompleted, key)
		completed = false
	}
	c.resolverStatsMu.Unlock()
	return completed
}

func (c *Client) trackResolverFailure(packet []byte, addr *net.UDPAddr, localAddr string, failedAt time.Time) {
	c.trackResolverFailureOver(packet, addr, localAddr, c.activeTransport(), failedAt)
}

func (c *Client) trackResolverFailureOver(packet []byte, addr *net.UDPAddr, localAddr string, transport resolverTransport, failedAt time.Time) {
	c.trackResolverFailureSeverityOver(packet, addr, localAddr, transport, failedAt, false)
}

func (c *Client) trackResolverHardFailureOver(packet []byte, addr *net.UDPAddr, localAddr string, transport resolverTransport, failedAt time.Time) {
	c.trackResolverFailureSeverityOver(packet, addr, localAddr, transport, failedAt, true)
}

func (c *Client) trackResolverFailureSeverityOver(
	packet []byte,
	addr *net.UDPAddr,
	localAddr string,
	transport resolverTransport,
	failedAt time.Time,
	hard bool,
) {
	if c == nil || len(packet) < 2 || addr == nil {
		return
	}

	fingerprint := dnsQuestionFingerprint(packet)
	key := resolverSampleKey{
		resolverAddr:        addr.String(),
		localAddr:           localAddr,
		dnsID:               binary.BigEndian.Uint16(packet[:2]),
		transport:           transport,
		questionFingerprint: fingerprint,
	}

	c.resolverStatsMu.Lock()
	actualKey, sample, ok := c.resolverSampleLocked(key)
	if ok && sample.questionFingerprint != 0 && sample.questionFingerprint != fingerprint {
		ok = false
	}
	if ok {
		delete(c.resolverPending, actualKey)
	}
	c.resolverStatsMu.Unlock()

	if !ok || sample.serverKey == "" {
		return
	}
	if sample.timedOut {
		return
	}

	c.recordResolverHealthEvent(sample.serverKey, false, failedAt)
	if hard {
		c.noteResolverTransportHardFailure(sample.serverKey, sample.transport, failedAt)
	} else {
		c.noteResolverTransportFailure(sample.serverKey, sample.transport, failedAt)
	}
}

// resolverSampleLocked returns the exact fingerprinted sample, falling back to
// a zero-fingerprint entry for legacy/tests that predate question-keyed samples.
// The caller must hold resolverStatsMu for reading or writing.
func (c *Client) resolverSampleLocked(key resolverSampleKey) (resolverSampleKey, resolverSample, bool) {
	if sample, ok := c.resolverPending[key]; ok {
		return key, sample, true
	}
	if key.questionFingerprint != 0 {
		legacy := key
		legacy.questionFingerprint = 0
		if sample, ok := c.resolverPending[legacy]; ok {
			return legacy, sample, true
		}
	}
	for candidate, sample := range c.resolverPending {
		if candidate.resolverAddr == key.resolverAddr &&
			candidate.localAddr == key.localAddr &&
			candidate.dnsID == key.dnsID &&
			candidate.transport == key.transport {
			return candidate, sample, true
		}
	}
	return resolverSampleKey{}, resolverSample{}, false
}

func dnsQuestionFingerprint(packet []byte) uint64 {
	if len(packet) < 12 || binary.BigEndian.Uint16(packet[4:6]) != 1 {
		return 0
	}
	const fnvOffset64 = uint64(14695981039346656037)
	const fnvPrime64 = uint64(1099511628211)
	hash := fnvOffset64
	offset := 12
	for {
		if offset >= len(packet) {
			return 0
		}
		lengthByte := packet[offset]
		length := int(lengthByte)
		offset++
		hash ^= uint64(lengthByte)
		hash *= fnvPrime64
		if length == 0 {
			break
		}
		if length&0xc0 != 0 || length > 63 || offset+length > len(packet) {
			return 0
		}
		for _, labelByte := range packet[offset : offset+length] {
			if labelByte >= 'A' && labelByte <= 'Z' {
				labelByte += 'a' - 'A'
			}
			hash ^= uint64(labelByte)
			hash *= fnvPrime64
		}
		offset += length
	}
	if offset+4 > len(packet) {
		return 0
	}
	for _, b := range packet[offset : offset+4] {
		hash ^= uint64(b)
		hash *= fnvPrime64
	}
	return hash
}

func (c *Client) collectExpiredResolverTimeouts(now time.Time) {
	if c == nil {
		return
	}
	c.resolverStatsMu.Lock()
	timeoutObservations := c.pruneResolverSamplesLocked(now)
	c.resolverStatsMu.Unlock()
	for _, observation := range timeoutObservations {
		c.noteResolverTimeout(observation.serverKey, observation.at)
		c.noteResolverTransportFailure(observation.serverKey, observation.transport, observation.at)
		c.replayPendingResolverSample(observation.key, failureReplayMaxDepth)
	}
}

func (c *Client) resolverRequestTimeout() time.Duration {
	if c == nil {
		return 5 * time.Second
	}
	timeout := c.tunnelPacketTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if window := c.autoDisableTimeoutWindow(); window > 0 && window < timeout {
		timeout = window
	}
	if timeout < 500*time.Millisecond {
		timeout = 500 * time.Millisecond
	}
	return timeout
}

// resolverPathRequestTimeout shortens blackhole detection only after a path has
// enough successful RTT history. Late replies remain claimable during the
// existing grace window, so a transient DPI delay can repair the timeout sample
// instead of permanently disabling a working resolver.
func (c *Client) resolverPathRequestTimeout(serverKey string, transport resolverTransport) time.Duration {
	base := c.resolverRequestTimeout()
	if c == nil || serverKey == "" || !validResolverTransport(transport) {
		return base
	}
	c.resolverTransportMu.Lock()
	state := c.resolverTransportStateLocked(serverKey)
	score := pathScoreFor(state, transport)
	successes, rtt := score.successes, score.rttEWMA
	c.resolverTransportMu.Unlock()
	if successes < transportSpeedSampleThreshold || rtt <= 0 {
		return base
	}
	adaptive := 6*rtt + 500*time.Millisecond
	if adaptive < 1500*time.Millisecond {
		adaptive = 1500 * time.Millisecond
	}
	if adaptive > base {
		return base
	}
	return adaptive
}

func (c *Client) resolverLateResponseGrace(timeout time.Duration) time.Duration {
	if timeout <= 0 {
		timeout = c.resolverRequestTimeout()
	}
	grace := timeout * 3
	if grace < time.Second {
		grace = time.Second
	}
	maxTTL := c.resolverSampleTTL()
	if grace > maxTTL {
		grace = maxTTL
	}
	return grace
}

func (c *Client) pruneResolverSamplesLocked(now time.Time) []resolverTimeoutObservation {
	if c == nil || len(c.resolverPending) == 0 {
		return nil
	}

	absoluteCutoff := now.Add(-c.resolverSampleTTL())
	requestTimeout := c.resolverRequestTimeout()
	lateGrace := c.resolverLateResponseGrace(requestTimeout)
	var timeoutObservations []resolverTimeoutObservation
	for key, expiresAt := range c.resolverCompleted {
		if !expiresAt.After(now) {
			delete(c.resolverCompleted, key)
		}
	}
	for key, sample := range c.resolverPending {
		if !sample.timedOut {
			timeoutAt := sample.timeoutAt
			if timeoutAt.IsZero() {
				timeoutAt = sample.sentAt.Add(requestTimeout)
			}
			if !timeoutAt.After(now) {
				sample.timedOut = true
				sample.timedOutAt = timeoutAt
				if sample.timedOutAt.After(now) {
					sample.timedOutAt = now
				}
				sample.evictAfter = sample.timedOutAt.Add(lateGrace)
				c.resolverPending[key] = sample
				if sample.serverKey != "" {
					timeoutObservations = append(timeoutObservations, resolverTimeoutObservation{
						serverKey: sample.serverKey,
						transport: sample.transport,
						at:        sample.timedOutAt,
						key:       key,
					})
				}
			}
			if sample.sentAt.Before(absoluteCutoff) {
				delete(c.resolverPending, key)
			}
			continue
		}

		if !sample.evictAfter.IsZero() && !sample.evictAfter.After(now) {
			delete(c.resolverPending, key)
			continue
		}
		if sample.sentAt.Before(absoluteCutoff) {
			delete(c.resolverPending, key)
		}
	}
	return timeoutObservations
}

func (c *Client) evictResolverPendingLocked(evictCount int) {
	if c == nil || evictCount <= 0 || len(c.resolverPending) == 0 {
		return
	}

	type pendingEntry struct {
		key    resolverSampleKey
		sample resolverSample
	}

	entries := make([]pendingEntry, 0, len(c.resolverPending))
	for key, sample := range c.resolverPending {
		entries = append(entries, pendingEntry{key: key, sample: sample})
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].sample.timedOut != entries[j].sample.timedOut {
			return entries[i].sample.timedOut
		}
		if !entries[i].sample.sentAt.Equal(entries[j].sample.sentAt) {
			return entries[i].sample.sentAt.Before(entries[j].sample.sentAt)
		}
		if entries[i].key.resolverAddr != entries[j].key.resolverAddr {
			return entries[i].key.resolverAddr < entries[j].key.resolverAddr
		}
		return entries[i].key.dnsID < entries[j].key.dnsID
	})

	if evictCount > len(entries) {
		evictCount = len(entries)
	}
	for i := 0; i < evictCount; i++ {
		delete(c.resolverPending, entries[i].key)
	}
}
