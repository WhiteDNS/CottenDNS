package clientui

import (
	"strings"
	"testing"
	"time"

	"cottendns-go/internal/client"
)

func TestShouldUseExplicitModes(t *testing.T) {
	if !ShouldUse("tui") {
		t.Fatal("forced TUI mode was ignored")
	}
	if ShouldUse("plain") {
		t.Fatal("plain mode enabled the TUI")
	}
}

func TestDashboardRendersNarrowAndWideLayouts(t *testing.T) {
	for _, width := range []int{40, 80, 120} {
		m := model{
			width: width, height: 28, started: time.Now().Add(-time.Minute),
			status: client.StatusSnapshot{
				Phase: "connected", Transport: "UDP", FamilyMode: "auto",
				ConfiguredResolvers: 4, ConfiguredIPv4: 2, ConfiguredIPv6: 2,
				ActiveResolvers: 2, ActiveIPv4: 2, UploadMTU: 180, DownloadMTU: 1200,
			},
			logs: []string{"[INFO] listener ready", "[WARN] IPv6 fallback active"},
		}
		view := m.View()
		for _, want := range []string{"CottenDNS", "CONNECTED", "RESOLVERS", "ACTIVITY"} {
			if !strings.Contains(view, want) {
				t.Fatalf("width %d view missing %q", width, want)
			}
		}
	}
}

func TestPhaseProgressRepresentsConnectionState(t *testing.T) {
	connected := phaseProgress("connected", 10)
	starting := phaseProgress("starting", 10)
	if connected == starting || !strings.Contains(connected, "━━━━━━━━━━") {
		t.Fatalf("unexpected phase bars: connected=%q starting=%q", connected, starting)
	}
}

func TestCompactLogLineRemovesANSIMetadata(t *testing.T) {
	line := "2026/08/12 12:00:00 \x1b[36m[CottenDns Client]\x1b[0m \x1b[32m[INFO]\x1b[0m connected"
	got := compactLogLine(line)
	if strings.Contains(got, "\x1b") || !strings.Contains(got, "connected") {
		t.Fatalf("compact log = %q", got)
	}
}

func TestLogWriterKeepsWholeLines(t *testing.T) {
	w := newLogWriter()
	_, _ = w.Write([]byte("one"))
	_, _ = w.Write([]byte(" line\ntwo lines\n"))
	if got := <-w.lines; got != "one line" {
		t.Fatalf("first line = %q", got)
	}
	if got := <-w.lines; got != "two lines" {
		t.Fatalf("second line = %q", got)
	}
}
