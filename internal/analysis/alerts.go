package analysis

import (
	"sync"
	"time"

	"github.com/adnancyber-he/netsentinel/pkg/models"
)

type AlertEngine struct {
	mu     sync.RWMutex
	alerts []models.Alert

	// Port scan tracking: srcIP -> set of dstPorts within window
	scanWindow time.Duration
	scans      map[string]map[uint16]time.Time
	scanCount  int
}

func NewAlertEngine() *AlertEngine {
	ae := &AlertEngine{
		scanWindow: 5 * time.Second,
		scans:      make(map[string]map[uint16]time.Time),
		scanCount:  20,
	}
	go ae.cleanupLoop()
	return ae
}

func (ae *AlertEngine) Inspect(p models.Packet) {
	ae.checkPortScan(p)
}

func (ae *AlertEngine) checkPortScan(p models.Packet) {
	if p.Protocol != "TCP" && p.Protocol != "UDP" {
		return
	}
	now := p.Timestamp
	src := p.SrcIP.String()

	ae.mu.Lock()
	defer ae.mu.Unlock()

	if _, ok := ae.scans[src]; !ok {
		ae.scans[src] = make(map[uint16]time.Time)
	}
	ae.scans[src][p.DstPort] = now

	// Count unique ports within window
	count := 0
	for _, t := range ae.scans[src] {
		if now.Sub(t) <= ae.scanWindow {
			count++
		}
	}
	if count >= ae.scanCount {
		ae.alerts = append(ae.alerts, models.Alert{
			Timestamp: now,
			Severity:  models.SevHigh,
			Category:  "Port Scan",
			Message:   "Possible port scan detected",
			SrcIP:     src,
			DstIP:     p.DstIP.String(),
		})
		// Reset to avoid spam
		ae.scans[src] = make(map[uint16]time.Time)
	}
}

func (ae *AlertEngine) Snapshot() []models.Alert {
	ae.mu.RLock()
	defer ae.mu.RUnlock()
	out := make([]models.Alert, len(ae.alerts))
	copy(out, ae.alerts)
	return out
}

func (ae *AlertEngine) cleanupLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-2 * ae.scanWindow)
		ae.mu.Lock()
		for src, ports := range ae.scans {
			for port, t := range ports {
				if t.Before(cutoff) {
					delete(ports, port)
				}
			}
			if len(ports) == 0 {
				delete(ae.scans, src)
			}
		}
		ae.mu.Unlock()
	}
}