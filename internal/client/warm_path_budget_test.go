package client

import (
	"testing"
	"time"
)

func newWarmPathBudgetClient(now time.Time) *Client {
	c := &Client{
		txChannel:        make(chan rawOutboundTask, 100),
		encodedTXChannel: make(chan encodedOutboundTask, 100),
		rxChannel:        make(chan asyncReadPacket, 100),
		resolverPending:  make(map[resolverSampleKey]resolverSample),
	}
	c.warmPathLastScanUnix.Store(now.UnixNano())
	return c
}

func TestWarmPathExplorationUsesBoundedForegroundBudget(t *testing.T) {
	now := time.Now()
	c := newWarmPathBudgetClient(now)
	c.runtimeOriginalSends.Store(warmPathForegroundFramesPerScan - 1)
	if c.allowWarmPathExploration(now.Add(time.Minute), 30*time.Second) {
		t.Fatal("warm-path scan ran before its foreground capacity budget accrued")
	}
	c.runtimeOriginalSends.Add(1)
	if !c.allowWarmPathExploration(now.Add(time.Minute), 30*time.Second) {
		t.Fatal("warm-path scan did not run after its bounded budget accrued")
	}
	if c.allowWarmPathExploration(now.Add(time.Minute), 30*time.Second) {
		t.Fatal("warm-path budget was charged more than once")
	}
}

func TestWarmPathExplorationStopsDuringCongestion(t *testing.T) {
	now := time.Now()
	c := newWarmPathBudgetClient(now)
	c.runtimeOriginalSends.Store(warmPathForegroundFramesPerScan)
	for i := 0; i < cap(c.txChannel)/4; i++ {
		c.txChannel <- rawOutboundTask{}
	}
	if c.allowWarmPathExploration(now.Add(time.Minute), 30*time.Second) {
		t.Fatal("warm-path scan competed with a congested foreground queue")
	}
}

func TestWarmPathExplorationRefreshesStaleIdlePaths(t *testing.T) {
	now := time.Now()
	c := newWarmPathBudgetClient(now)
	if !c.allowWarmPathExploration(now.Add(2*time.Minute), 30*time.Second) {
		t.Fatal("completely idle alternate paths were allowed to become stale")
	}
	c.encodedTXChannel <- encodedOutboundTask{}
	c.warmPathLastScanUnix.Store(now.UnixNano())
	if c.allowWarmPathExploration(now.Add(2*time.Minute), 30*time.Second) {
		t.Fatal("stale-path exception displaced queued user traffic")
	}
}
