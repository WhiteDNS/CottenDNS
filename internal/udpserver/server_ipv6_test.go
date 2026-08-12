package udpserver

import (
	"net"
	"testing"

	"cottendns-go/internal/config"
)

func TestServerListenUDPIPv6(t *testing.T) {
	s := &Server{cfg: config.ServerConfig{UDPReaders: 1}}
	conns, err := s.listenUDP(&net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer func() {
		for _, conn := range conns {
			_ = conn.Close()
		}
	}()
	if len(conns) != 1 {
		t.Fatalf("IPv6 listeners = %d, want 1", len(conns))
	}
	addr := conns[0].LocalAddr().(*net.UDPAddr)
	if addr.IP.To4() != nil {
		t.Fatalf("server listener is not IPv6: %v", addr)
	}
}
