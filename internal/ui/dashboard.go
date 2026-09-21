package ui

import (
	"fmt"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
	"github.com/adnancyber-he/netsentinel/internal/analysis"
	"github.com/adnancyber-he/netsentinel/pkg/models"
)

type Dashboard struct {
	app     *tview.Application
	stats   *models.Stats
	flows   *analysis.FlowTracker
	alerts  *analysis.AlertEngine
	text    *tview.TextView
	stopCh  chan struct{}
}

func NewDashboard(stats *models.Stats, flows *analysis.FlowTracker, alerts *analysis.AlertEngine) *Dashboard {
	return &Dashboard{
		app:    tview.NewApplication(),
		stats:  stats,
		flows:  flows,
		alerts: alerts,
		stopCh: make(chan struct{}),
	}
}

func (d *Dashboard) Run() error {
	d.text = tview.NewTextView().
		SetDynamicColors(true).
		SetChangedFunc(func() { d.app.Draw() })

	layout := tview.NewFlex().
		AddItem(d.text, 0, 1, true)

	go d.refreshLoop()

	d.app.SetRoot(layout, true).EnableMouse(false)

	// Quit on 'q' or Ctrl+C
	d.app.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		if ev.Key() == tcell.KeyCtrlC || ev.Rune() == 'q' {
			close(d.stopCh)
			d.app.Stop()
		}
		return ev
	})

	return d.app.Run()
}

func (d *Dashboard) refreshLoop() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.render()
		}
	}
}

func (d *Dashboard) render() {
	uptime := time.Since(d.stats.StartTime).Round(time.Second)
	flows := d.flows.Snapshot()
	alerts := d.alerts.Snapshot()

	var b string
	b += "[yellow]╔══════════════════════════════════════════════════════════════╗\n"
	b += "[yellow]║  [white]NetSentinel v0.1 (Go)  [yellow]│  Live Capture Dashboard       [yellow]║\n"
	b += "[yellow]╚══════════════════════════════════════════════════════════════╝\n\n"

	b += fmt.Sprintf("[green]Total Packets: [white]%d\n", d.stats.TotalPackets)
	b += fmt.Sprintf("[green]Total Bytes:   [white]%d\n", d.stats.TotalBytes)
	b += fmt.Sprintf("[green]Active Flows:  [white]%d\n", len(flows))
	b += fmt.Sprintf("[green]Alerts:        [white]%d\n", len(alerts))
	b += fmt.Sprintf("[green]Uptime:        [white]%s\n\n", uptime)

	b += "[yellow]─── Recent Alerts ────────────────────────────────────────────\n"
	n := len(alerts)
	if n > 5 { n = 5 }
	for i := n - 1; i >= 0; i-- {
		a := alerts[i]
		color := "red"
		if a.Severity == models.SevHigh { color = "orange" }
		b += fmt.Sprintf("[%s][%s][white] %s — %s\n", color, a.Severity, a.Category, a.Message)
	}
	if n == 0 {
		b += "[gray]  (no alerts yet)\n"
	}

	b += "\n[yellow]─── Top Flows ────────────────────────────────────────────────\n"
	m := len(flows)
	if m > 10 { m = 10 }
	for i := 0; i < m; i++ {
		f := flows[i]
		b += fmt.Sprintf("[white]%s:%d → %s:%d [%s] [green]%d pkts / %d bytes\n",
			f.Key.SrcIP, f.Key.SrcPort, f.Key.DstIP, f.Key.DstPort, f.Key.Proto, f.Packets, f.Bytes)
	}

	b += "\n[gray](press 'q' to quit)\n"

	d.app.QueueUpdateDraw(func() {
		d.text.SetText(b)
	})
}