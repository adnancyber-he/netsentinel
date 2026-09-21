package models

import (
	"net"
	"time"

	"github.com/google/gopacket"
)

type Packet struct {
	Timestamp time.Time
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Length    uint32
	Payload   []byte
	Raw       gopacket.Packet
}

type FlowKey struct {
	SrcIP   string
	DstIP   string
	SrcPort uint16
	DstPort uint16
	Proto   string
}

type Flow struct {
	Key        FlowKey
	Packets    uint64
	Bytes      uint64
	FirstSeen  time.Time
	LastSeen   time.Time
}

type Severity string

const (
	SevLow      Severity = "LOW"
	SevMedium   Severity = "MEDIUM"
	SevHigh     Severity = "HIGH"
	SevCritical Severity = "CRITICAL"
)

type Alert struct {
	Timestamp time.Time
	Severity  Severity
	Category  string
	Message   string
	SrcIP     string
	DstIP     string
}

type Stats struct {
	TotalPackets uint64
	TotalBytes   uint64
	StartTime    time.Time
	LastUpdated  time.Time
}