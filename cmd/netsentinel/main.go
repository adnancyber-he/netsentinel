package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"github.com/adnancyber-he/netsentinel/internal/analysis"
	"github.com/adnancyber-he/netsentinel/internal/capture"
	"github.com/adnancyber-he/netsentinel/internal/report"
	"github.com/adnancyber-he/netsentinel/internal/ui"
	"github.com/adnancyber-he/netsentinel/pkg/models"
)

var (
	flagIface   string
	flagFilter  string
	flagFile    string
	flagList    bool
	flagNoUI    bool
	flagOutDir  string
)

func main() {
	root := &cobra.Command{
		Use:   "netsentinel",
		Short: "A cross-platform packet sniffer & traffic analyzer",
		RunE:  run,
	}

	root.Flags().StringVarP(&flagIface, "interface", "i", "", "Interface to capture on")
	root.Flags().StringVarP(&flagFilter, "filter", "f", "", "BPF filter")
	root.Flags().StringVarP(&flagFile, "read", "r", "", "Read from .pcap file")
	root.Flags().BoolVarP(&flagList, "list", "L", false, "List interfaces")
	root.Flags().BoolVarP(&flagNoUI, "no-ui", "n", false, "Headless mode")
	root.Flags().StringVarP(&flagOutDir, "out", "o", ".", "Output directory for reports")

	if err := root.Execute(); err != nil {
		log.Fatal(err)
	}
}

func run(cmd *cobra.Command, args []string) error {
	if flagList {
		ifaces, err := capture.ListInterfaces()
		if err != nil {
			return err
		}
		fmt.Println("Available interfaces:")
		for _, i := range ifaces {
			fmt.Printf("  %-20s %s\n", i.Name, i.Description)
		}
		return nil
	}

	var cap *capture.Capture
	var err error
	if flagFile != "" {
		cap, err = capture.NewOffline(flagFile)
	} else if flagIface != "" {
		cap, err = capture.NewLive(flagIface, flagFilter, 1600, true)
	} else {
		return fmt.Errorf("either -i <iface> or -r <pcap> is required")
	}
	if err != nil {
		return err
	}
	defer cap.Close()

	stats := &models.Stats{StartTime: time.Now()}
	flows := analysis.NewFlowTracker(2 * time.Minute)
	alerts := analysis.NewAlertEngine()

	// Ingestion pipeline
	go func() {
		for p := range cap.Packets() {
			stats.TotalPackets++
			stats.TotalBytes += uint64(p.Length)
			stats.LastUpdated = time.Now()
			flows.Track(p)
			alerts.Inspect(p)
		}
	}()

	// Graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		cap.Close()
	}()

	// Run UI or headless
	if !flagNoUI {
		dash := ui.NewDashboard(stats, flows, alerts)
		return dash.Run()
	}

	// Headless: wait until interrupt, then write report
	<-sigCh
	return report.WriteJSON(flagOutDir, flagIface, *stats, flows.Snapshot(), alerts.Snapshot())
}