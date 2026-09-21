package capture

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/adnancyber-he/netsentinel/pkg/models"
)

// Capture wraps live or offline packet sources.
type Capture struct {
	handle *pcap.Handle
	source *gopacket.PacketSource
}

// ListInterfaces returns all capturable interfaces.
func ListInterfaces() ([]pcap.Interface, error) {
	return pcap.FindAllDevs()
}

// NewLive opens a live capture on the given interface with optional BPF filter.
func NewLive(iface, bpf string, snaplen int32, promisc bool) (*Capture, error) {
	handle, err := pcap.OpenLive(iface, snaplen, promisc, pcap.BlockForever)
	if err != nil {
		return nil, err
	}
	if bpf != "" {
		if err := handle.SetBPFFilter(bpf); err != nil {
			handle.Close()
			return nil, err
		}
	}
	return &Capture{
		handle: handle,
		source: gopacket.NewPacketSource(handle, handle.LinkType()),
	}, nil
}

// NewOffline opens a .pcap file for analysis.
func NewOffline(path string) (*Capture, error) {
	handle, err := pcap.OpenOffline(path)
	if err != nil {
		return nil, err
	}
	return &Capture{
		handle: handle,
		source: gopacket.NewPacketSource(handle, handle.LinkType()),
	}, nil
}

// Packets returns a channel of parsed packets. Close the Capture to stop.
func (c *Capture) Packets() <-chan models.Packet {
	out := make(chan models.Packet, 1024)
	go func() {
		defer close(out)
		for pkt := range c.source.Packets() {
			parsed, ok := ParsePacket(pkt)
			if !ok {
				continue
			}
			out <- parsed
		}
	}()
	return out
}

// Close releases the underlying handle.
func (c *Capture) Close() {
	if c.handle != nil {
		c.handle.Close()
		log.Println("capture: closed")
	}
}