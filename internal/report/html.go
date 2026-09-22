package report

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/adnancyber-he/netsentinel/pkg/models"
)

// HTMLReportData is the view model passed to the template.
type HTMLReportData struct {
	Meta         Meta
	Stats        models.Stats
	Duration     string
	AvgPPS       float64
	AvgBPS       float64
	TopFlows     []models.Flow
	Alerts       []models.Alert
	ProtocolDist []ProtocolSlice
	SeverityDist []SeveritySlice
	TopSrcIPs    []IPCount
	TopDstIPs    []IPCount
}

type ProtocolSlice struct {
	Label string
	Count uint64
	Pct   float64
	Color string
}

type SeveritySlice struct {
	Label string
	Count int
	Pct   float64
	Color string
}

type IPCount struct {
	IP    string
	Count uint64
	Bytes uint64
}

// WriteHTML renders a self-contained HTML report to outDir.
func WriteHTML(outDir, iface string, stats models.Stats, flows []models.Flow, alerts []models.Alert) error {
	data := buildReportData(iface, stats, flows, alerts)

	fname := fmt.Sprintf("netsentinel_%s.html", time.Now().Format("20060102_150405"))
	path := filepath.Join(outDir, fname)

	var buf bytes.Buffer
	if err := htmlTmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("render template: %w", err)
	}
	return os.WriteFile(path, buf.Bytes(), 0644)
}

func buildReportData(iface string, stats models.Stats, flows []models.Flow, alerts []models.Alert) HTMLReportData {
	// Sort flows by bytes desc
	sort.Slice(flows, func(i, j int) bool { return flows[i].Bytes > flows[j].Bytes })

	// Sort alerts: severity desc, then timestamp desc
	sevRank := map[models.Severity]int{
		models.SevCritical: 4, models.SevHigh: 3, models.SevMedium: 2, models.SevLow: 1,
	}
	sort.Slice(alerts, func(i, j int) bool {
		if sevRank[alerts[i].Severity] != sevRank[alerts[j].Severity] {
			return sevRank[alerts[i].Severity] > sevRank[alerts[j].Severity]
		}
		return alerts[i].Timestamp.After(alerts[j].Timestamp)
	})

	// Duration & throughput
	dur := stats.LastUpdated.Sub(stats.StartTime)
	if dur <= 0 {
		dur = time.Second
	}
	avgPPS := float64(stats.TotalPackets) / dur.Seconds()
	avgBPS := float64(stats.TotalBytes) * 8 / dur.Seconds()

	// Protocol distribution
	protoCounts := map[string]uint64{}
	protoBytes := map[string]uint64{}
	for _, f := range flows {
		protoCounts[f.Key.Proto] += f.Packets
		protoBytes[f.Key.Proto] += f.Bytes
	}
	totalPkts := uint64(0)
	for _, c := range protoCounts {
		totalPkts += c
	}
	palette := []string{"#3b82f6", "#10b981", "#f59e0b", "#ef4444", "#8b5cf6", "#06b6d4", "#ec4899"}
	protos := make([]ProtocolSlice, 0, len(protoCounts))
	i := 0
	for label, count := range protoCounts {
		pct := 0.0
		if totalPkts > 0 {
			pct = float64(count) / float64(totalPkts) * 100
		}
		protos = append(protos, ProtocolSlice{
			Label: label, Count: count, Pct: pct, Color: palette[i%len(palette)],
		})
		i++
	}
	sort.Slice(protos, func(a, b int) bool { return protos[a].Count > protos[b].Count })

	// Severity distribution
	sevCounts := map[models.Severity]int{}
	for _, a := range alerts {
		sevCounts[a.Severity]++
	}
	sevColors := map[models.Severity]string{
		models.SevCritical: "#dc2626",
		models.SevHigh:     "#f97316",
		models.SevMedium:   "#eab308",
		models.SevLow:      "#22c55e",
	}
	totalAlerts := len(alerts)
	severities := make([]SeveritySlice, 0, 4)
	for _, s := range []models.Severity{models.SevCritical, models.SevHigh, models.SevMedium, models.SevLow} {
		c := sevCounts[s]
		pct := 0.0
		if totalAlerts > 0 {
			pct = float64(c) / float64(totalAlerts) * 100
		}
		severities = append(severities, SeveritySlice{
			Label: string(s), Count: c, Pct: pct, Color: sevColors[s],
		})
	}

	// Top src/dst IPs
	srcMap := map[string]*IPCount{}
	dstMap := map[string]*IPCount{}
	for _, f := range flows {
		s := srcMap[f.Key.SrcIP]
		if s == nil { s = &IPCount{IP: f.Key.SrcIP}; srcMap[f.Key.SrcIP] = s }
		s.Count += f.Packets
		s.Bytes += f.Bytes

		d := dstMap[f.Key.DstIP]
		if d == nil { d = &IPCount{IP: f.Key.DstIP}; dstMap[f.Key.DstIP] = d }
		d.Count += f.Packets
		d.Bytes += f.Bytes
	}
	srcs := mapToSorted(srcMap, 10)
	dsts := mapToSorted(dstMap, 10)

	return HTMLReportData{
		Meta: Meta{
			Tool:      "NetSentinel v0.1 (Go)",
			Interface: iface,
			Generated: time.Now(),
		},
		Stats:        stats,
		Duration:     dur.Round(time.Second).String(),
		AvgPPS:       avgPPS,
		AvgBPS:       avgBPS,
		TopFlows:     topN(flows, 25),
		Alerts:       alerts,
		ProtocolDist: protos,
		SeverityDist: severities,
		TopSrcIPs:    srcs,
		TopDstIPs:    dsts,
	}
}

func mapToSorted(m map[string]*IPCount, limit int) []IPCount {
	out := make([]IPCount, 0, len(m))
	for _, v := range m {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func topN(flows []models.Flow, n int) []models.Flow {
	if len(flows) > n {
		return flows[:n]
	}
	return flows
}