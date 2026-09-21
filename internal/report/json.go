package report

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/adnancyber-he/netsentinel/pkg/models"
)

type JSONReport struct {
	Meta       Meta           `json:"meta"`
	Stats      models.Stats   `json:"statistics"`
	TopFlows   []models.Flow  `json:"top_flows"`
	Alerts     []models.Alert `json:"alerts"`
}

type Meta struct {
	Tool      string    `json:"tool"`
	Interface string    `json:"interface"`
	Generated time.Time `json:"generated_at"`
}

func WriteJSON(path, iface string, stats models.Stats, flows []models.Flow, alerts []models.Alert) error {
	rep := JSONReport{
		Meta: Meta{
			Tool:      "NetSentinel v0.1 (Go)",
			Interface: iface,
			Generated: time.Now(),
		},
		Stats:    stats,
		TopFlows: flows,
		Alerts:   alerts,
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	fname := fmt.Sprintf("%s/netsentinel_%s.json", path, time.Now().Format("20060102_150405"))
	return os.WriteFile(fname, data, 0644)
}