# 🛡 NetSentinel

**A cross-platform packet sniffer & traffic analyzer — rewritten in Go.**

[![Build & Release](https://github.com/adnancyber-he/netsentinel/actions/workflows/main.yml/badge.svg)](https://github.com/adnancyber-he/netsentinel/actions/workflows/main.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/adnancyber-he/netsentinel)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macOS%20%7C%20windows-blue)]()
[![CodeQL](https://github.com/adnancyber-he/netsentinel/actions/workflows/codeql.yml/badge.svg)](https://github.com/adnancyber-he/netsentinel/actions/workflows/codeql.yml)
[![Dependabot](https://img.shields.io/badge/dependabot-enabled-brightgreen.svg?logo=dependabot)](https://github.com/adnancyber-he/netsentinel/network/dependencies)

> **v0.1 (Go)** — the original C++17 codebase has been retired in favor of a cleaner, more portable Go implementation.


## ✨ Features

| Feature | Description |
|---|---|
| **Live Capture** | Promiscuous-mode packet capture via libpcap / Npcap |
| **Protocol Dissection** | Ethernet → IPv4/IPv6 → TCP/UDP/ICMP → payload inspection |
| **Flow Tracking** | 5-tuple flow table with TTL-based eviction and per-flow counters |
| **Real-time TUI** | Terminal dashboard with live stats, alerts and top flows |
| **Alert Engine** | Pluggable detection rules (port scan built-in) |
| **Reports** | JSON report on graceful shutdown |
| **BPF Filters** | Full Berkeley Packet Filter support |
| **Offline Analysis** | Read and analyze `.pcap` files |
| **Cross-platform** | Linux, macOS and Windows — same codebase |



## 📸 Screenshots

### Live TUI Dashboard

![Live Dashboard](docs/screenshots/dashboard.png)

*Real-time capture on `eth0` showing packet counters, active flows, recent
alerts and top talkers.*

### Flow Table

![Flow Table](docs/screenshots/flows.png)

*5-tuple flow table sorted by bytes, with per-flow PPS and BPS.*

### Alerts View

![Alerts](docs/screenshots/alerts.png)

*Security alerts with severity badges — port scan, ARP spoof, SYN flood.*

### HTML Report

![HTML Report](docs/screenshots/report-html.png)

*Self-contained HTML report with KPI cards, protocol distribution chart
and alert breakdown.*

### JSON Report

![JSON Report](docs/screenshots/report-json.png)

*Machine-readable JSON output for integration with SIEM / log pipelines.*

---


## 🏗 Architecture

```
┌───────────────────────────────────────────────────────────────┐
│                       NetSentinel (Go)                        │
├──────────────┬───────────────┬──────────────┬────────────────┤
│   Capture    │   Parsing     │   Analysis   │   Output       │
│              │               │              │                │
│  capture.go  │  parser.go    │  flow.go     │  ui/           │
│  (gopacket)  │               │  alerts.go   │  report/       │
│              │  Ethernet     │              │                │
│  - Live      │  IPv4/IPv6    │  FlowTracker │  - TUI (tview) │
│  - pcap file │  TCP/UDP      │  AlertEngine │  - JSON report │
│  - BPF       │  ICMP/ARP     │              │                │
└──────────────┴───────────────┴──────────────┴────────────────┘
```

### Project Layout

```
netsentinel/
├── cmd/
│   └── netsentinel/
│       └── main.go              ← CLI entry point (cobra)
├── internal/
│   ├── capture/                 ← Live + offline capture, parsing
│   │   ├── capture.go
│   │   └── parser.go
│   ├── analysis/                ← Flow tracking, alert engine
│   │   ├── flow.go
│   │   └── alerts.go
│   ├── ui/                      ← TUI dashboard (tview)
│   │   └── dashboard.go
│   └── report/                  ← JSON reporter
│       └── json.go
├── pkg/
│   └── models/                  ← Shared types (Packet, Flow, Alert, Stats)
│       └── types.go
├── configs/                     ← Example configuration files
├── scripts/                     ← Build helpers
├── .github/workflows/
│   └── build.yml                ← Cross-platform CI/CD
├── go.mod
├── go.sum
└── README.md
```

---

## 📦 Prerequisites

NetSentinel uses `gopacket` with the `pcap` backend, which requires **CGO** and a native C library.

### Linux

```bash
sudo apt install -y libpcap-dev gcc
```

### macOS

```bash
brew install libpcap
```

### Windows

1. Download and install **[Npcap](https://npcap.com/#download)** (check "Install Npcap in WinPcap API-compatible Mode").
2. Download the **[Npcap SDK](https://npcap.com/#download)** and extract `Lib/x64/wpcap.lib` to the project root.
3. Set the linker flags before building:

```powershell
$env:CGO_ENABLED = "1"
$env:CGO_LDFLAGS = "-L$(Get-Location) -lwpcap"
```

---

## 🔨 Build

```bash
git clone https://github.com/adnancyber-he/netsentinel.git
cd netsentinel
go mod download
go build -trimpath -ldflags="-s -w" -o netsentinel ./cmd/netsentinel
```

### Linux capability (avoid `sudo` every time)

```bash
sudo setcap cap_net_raw,cap_net_admin+eip ./netsentinel
```

---

## 🚀 Usage

```bash
# List available interfaces
sudo ./netsentinel -L

# Capture all traffic on eth0 (live TUI dashboard)
sudo ./netsentinel -i eth0

# Capture with a BPF filter
sudo ./netsentinel -i eth0 -f "tcp port 443 or port 80"

# Headless mode (writes JSON on Ctrl+C)
sudo ./netsentinel -i eth0 -n -o ./reports

# Analyze an offline pcap file
./netsentinel -r capture.pcap -n -o ./analysis
```

### Flags

| Flag | Short | Description | Default |
|---|---|---|---|
| `--interface` | `-i` | Interface to capture on | — |
| `--filter` | `-f` | BPF filter expression | — |
| `--read` | `-r` | Read from `.pcap` file | — |
| `--list` | `-L` | List available interfaces | `false` |
| `--no-ui` | `-n` | Headless mode (no TUI) | `false` |
| `--out` | `-o` | Output directory for reports | `.` |

---

## 🖥 Dashboard

```
╔══════════════════════════════════════════════════════════════╗
║  NetSentinel v0.1 (Go)  │  Live Capture Dashboard            ║
╚══════════════════════════════════════════════════════════════╝

Total Packets: 12,540
Total Bytes:   8,391,040
Active Flows:  42
Alerts:        3
Uptime:        1m32s

─── Recent Alerts ────────────────────────────────────────────
[HIGH] Port Scan — Possible port scan detected

─── Top Flows ────────────────────────────────────────────────
192.168.1.5:54321 → 8.8.8.8:53 [UDP] 120 pkts / 14400 bytes
...

(press 'q' to quit)
```

### Keyboard Shortcuts

| Key | Action |
|---|---|
| `q` / `Ctrl+C` | Quit |

---

## 🚨 Detection Rules

| Rule | Severity | Trigger |
|---|---|---|
| **Port Scan** | HIGH | ≥ 20 unique ports within 5s from a single source |

More rules (ARP spoofing, SYN flood, cleartext credentials) are on the roadmap.

---

## 📄 Report Format

```json
{
  "meta": {
    "tool": "NetSentinel v0.1 (Go)",
    "interface": "eth0",
    "generated_at": "2026-03-01T12:34:56Z"
  },
  "statistics": {
    "TotalPackets": 12540,
    "TotalBytes": 8391040,
    "StartTime": "2026-03-01T12:30:00Z",
    "LastUpdated": "2026-03-01T12:34:55Z"
  },
  "top_flows": [
    {
      "Key": { "SrcIP": "192.168.1.5", "DstIP": "8.8.8.8", "SrcPort": 54321, "DstPort": 53, "Proto": "UDP" },
      "Packets": 120,
      "Bytes": 14400
    }
  ],
  "alerts": [
    {
      "Timestamp": "2026-03-01T12:33:10Z",
      "Severity": "HIGH",
      "Category": "Port Scan",
      "Message": "Possible port scan detected",
      "SrcIP": "10.0.0.42",
      "DstIP": "192.168.1.5"
    }
  ]
}
```

---

## 🧪 Testing

```bash
go test ./...
go vet ./...
```

---

## 🛠 CI/CD

Every push and tag triggers a matrix build across:

- Linux `amd64` / `arm64`
- macOS `amd64` (Intel) / `arm64` (Apple Silicon)
- Windows `amd64`

Tagged releases (`v*`) automatically publish binaries to GitHub Releases. See [`.github/workflows/build.yml`](.github/workflows/build.yml).

---

## 🗺 Roadmap

- [x] Live + offline capture
- [x] Protocol parsing (Eth / IP / TCP / UDP)
- [x] Flow tracking
- [x] Port-scan detection
- [x] JSON report
- [x] Cross-platform CI/CD
- [ ] HTML report with charts
- [ ] Additional detection rules (ARP spoof, SYN flood, cleartext creds)
- [ ] DNS / HTTP / TLS deep dissection
- [ ] Plugin system (`hashicorp/go-plugin`)
- [ ] YAML configuration file
- [ ] Multi-tab TUI (Overview / Flows / Alerts / Protocols)
- [ ] Unit + integration tests

---

## 🤝 Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

```bash
git checkout -b feature/my-feature
go test ./...
git commit -m "feat: add my feature"
git push origin feature/my-feature
```

---

## 📜 License

[MIT](LICENSE) — free for personal and commercial use.

---

## 🙏 Acknowledgements

- [gopacket](https://github.com/google/gopacket) — packet capture & decoding
- [tview](https://github.com/rivo/tview) + [tcell](https://github.com/gdamore/tcell) — terminal UI
- [cobra](https://github.com/spf13/cobra) — CLI framework
- [libpcap](https://www.tcpdump.org/) / [Npcap](https://npcap.com/) — the underlying capture engines

