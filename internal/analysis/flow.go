package analysis

import (
	"sync"
	"time"

	"github.com/adnancyber-he/netsentinel/pkg/models"
)

type FlowTracker struct {
	mu    sync.RWMutex
	flows map[models.FlowKey]*models.Flow
	ttl   time.Duration
}

func NewFlowTracker(ttl time.Duration) *FlowTracker {
	ft := &FlowTracker{
		flows: make(map[models.FlowKey]*models.Flow),
		ttl:   ttl,
	}
	go ft.evictLoop()
	return ft
}

func (ft *FlowTracker) Track(p models.Packet) {
	key := models.FlowKey{
		SrcIP:   p.SrcIP.String(),
		DstIP:   p.DstIP.String(),
		SrcPort: p.SrcPort,
		DstPort: p.DstPort,
		Proto:   p.Protocol,
	}

	ft.mu.Lock()
	defer ft.mu.Unlock()

	f, ok := ft.flows[key]
	if !ok {
		f = &models.Flow{Key: key, FirstSeen: p.Timestamp}
		ft.flows[key] = f
	}
	f.Packets++
	f.Bytes += uint64(p.Length)
	f.LastSeen = p.Timestamp
}

func (ft *FlowTracker) Snapshot() []models.Flow {
	ft.mu.RLock()
	defer ft.mu.RUnlock()

	out := make([]models.Flow, 0, len(ft.flows))
	for _, f := range ft.flows {
		out = append(out, *f)
	}
	return out
}

func (ft *FlowTracker) evictLoop() {
	ticker := time.NewTicker(ft.ttl / 2)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-ft.ttl)
		ft.mu.Lock()
		for k, f := range ft.flows {
			if f.LastSeen.Before(cutoff) {
				delete(ft.flows, k)
			}
		}
		ft.mu.Unlock()
	}
}