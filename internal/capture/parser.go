package capture

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/adnancyber-he/netsentinel/pkg/models"
)

// ParsePacket converts a gopacket.Packet into our decoupled model.
func ParsePacket(pkt gopacket.Packet) (models.Packet, bool) {
	p := models.Packet{
		Timestamp: pkt.Metadata().Timestamp,
		Length:    uint32(pkt.Metadata().Length),
	}

	// Network layer
	if ip4 := pkt.Layer(layers.LayerTypeIPv4); ip4 != nil {
		l := ip4.(*layers.IPv4)
		p.SrcIP = l.SrcIP
		p.DstIP = l.DstIP
		p.Protocol = l.Protocol.String()
	} else if ip6 := pkt.Layer(layers.LayerTypeIPv6); ip6 != nil {
		l := ip6.(*layers.IPv6)
		p.SrcIP = l.SrcIP
		p.DstIP = l.DstIP
		p.Protocol = l.NextHeader.String()
	} else {
		return p, false
	}

	// Transport layer
	if tcp := pkt.Layer(layers.LayerTypeTCP); tcp != nil {
		l := tcp.(*layers.TCP)
		p.SrcPort = uint16(l.SrcPort)
		p.DstPort = uint16(l.DstPort)
		p.Protocol = "TCP"
		p.Payload = l.Payload
	} else if udp := pkt.Layer(layers.LayerTypeUDP); udp != nil {
		l := udp.(*layers.UDP)
		p.SrcPort = uint16(l.SrcPort)
		p.DstPort = uint16(l.DstPort)
		p.Protocol = "UDP"
		p.Payload = l.Payload
	}

	return p, true
}