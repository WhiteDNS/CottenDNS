package client

import (
	"encoding/binary"
	"strings"
	"testing"

	DnsParser "cottendns-go/internal/dnsparser"
	Enums "cottendns-go/internal/enums"
	"cottendns-go/internal/security"
)

func TestEncodedCharsForPayloadUsesWorstCaseUploadPacketType(t *testing.T) {
	c := createTestClient(t)

	got := c.encodedCharsForPayload(120)
	want := c.encodedCharsForPacketPayload(maxUploadProbePacketType, 120)
	if got != want {
		t.Fatalf("expected worst-case encoded char count, got=%d want=%d", got, want)
	}
}

func TestEncodedCharsForPayloadMatchesMaxUploadProbeCapacityModel(t *testing.T) {
	c := createTestClient(t)

	payloadLen := 120
	if !c.canBuildUploadPayload("example.com", payloadLen) {
		t.Fatalf("expected payload length %d to fit generated upload MTU question", payloadLen)
	}

	got := c.encodedCharsForPayload(payloadLen)
	if got <= 0 {
		t.Fatal("expected encoded char count to be positive")
	}
}

func TestBuildMTUProbePayloadWritesModeAndProbeCodeWithoutFillingTail(t *testing.T) {
	c := createTestClient(t)

	payload, code, useBase64, err := c.buildMTUProbePayload(16)
	if err != nil {
		t.Fatalf("buildMTUProbePayload returned error: %v", err)
	}
	if useBase64 {
		t.Fatal("expected raw response mode for test client")
	}
	if len(payload) != 16 {
		t.Fatalf("unexpected payload length: got=%d want=%d", len(payload), 16)
	}
	if want := uint8(mtuProbeRawResponse | security.DownstreamEncryptedFlag); payload[0] != want {
		t.Fatalf("unexpected mode byte: got=%d want=%d", payload[0], want)
	}
	if got := binary.BigEndian.Uint32(payload[1 : 1+mtuProbeCodeLength]); got != code {
		t.Fatalf("unexpected probe code in payload: got=%d want=%d", got, code)
	}
	for i, value := range payload[1+mtuProbeCodeLength:] {
		if value != 0 {
			t.Fatalf("expected zero-filled tail at offset %d, got=%d", i+(1+mtuProbeCodeLength), value)
		}
	}
}

func TestMTUProbeQNameLimitCapsLabelLengthAndCapacity(t *testing.T) {
	c := createTestClient(t)
	const domain = "example.com"
	c.cfg.MTUTestMaxQNameLength = 30
	limited := c.maxUploadMTUPayload(domain)
	if limited <= 0 {
		t.Fatalf("expected some upload capacity with 30-character labels, got %d", limited)
	}
	if !c.canBuildUploadPayload(domain, limited) {
		t.Fatalf("computed capacity %d does not fit under DNS name limit", limited)
	}
	if c.canBuildUploadPayload(domain, limited+1) {
		t.Fatalf("payload beyond computed capacity %d unexpectedly fits", limited)
	}
	payload, _, _, err := c.buildMTUProbePayload(limited)
	if err != nil {
		t.Fatalf("buildMTUProbePayload returned error: %v", err)
	}
	query, err := c.buildMTUProbeQuery(domain, Enums.PACKET_MTU_UP_REQ, payload)
	if err != nil {
		t.Fatalf("buildMTUProbeQuery returned error: %v", err)
	}
	parsed, err := DnsParser.ParsePacketLite(query)
	if err != nil || !parsed.HasQuestion {
		t.Fatalf("ParsePacketLite failed: parsed=%+v err=%v", parsed, err)
	}
	name := strings.TrimSuffix(parsed.FirstQuestion.Name, ".")
	payloadName := strings.TrimSuffix(name, "."+domain)
	for _, label := range strings.Split(payloadName, ".") {
		if len(label) > 30 {
			t.Fatalf("MTU QNAME label length %d exceeds configured limit 30", len(label))
		}
	}

	c.cfg.MTUTestMaxQNameLength = 0
	if !c.canBuildUploadPayload(domain, limited+1) {
		t.Fatal("unset per-probe label limit should preserve the existing capacity behavior")
	}
}
