# Security Policy

## Supported Versions

NetSentinel is under active development. Security fixes are applied to the
latest released minor version. Older releases may not receive patches.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

If you are running from `main`, always pull the latest commit before
reporting an issue.

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately using one of these channels:

1. **GitHub Security Advisories** (preferred)  
   https://github.com/adnancyber-he/netsentinel/security/advisories/new

2. **Email**  
   Send details to the maintainer listed in `go.mod` / GitHub profile.
   Encrypt sensitive reports with the maintainer's PGP key if available.

### What to include

- A clear description of the vulnerability and its impact
- Affected version(s) and platform(s)
- Step-by-step reproduction instructions
- A proof-of-concept (code, pcap, command line) if possible
- Any suggested mitigation or fix
- Whether you would like public credit

### What to expect

| Stage | Timeframe |
| --- | --- |
| Acknowledgement of report | within 72 hours |
| Initial assessment & severity triage | within 7 days |
| Fix or mitigation plan | within 30 days for HIGH/CRITICAL |
| Public disclosure | coordinated with reporter |

We follow **coordinated disclosure**. We will credit you in the release
notes and the advisory unless you request otherwise.

---

## Scope

### In scope

- NetSentinel binaries and source code in this repository
- The build and release pipeline (GitHub Actions workflows)
- Bundled configuration files and scripts

### Out of scope

- Vulnerabilities in upstream dependencies  
  (report to [gopacket](https://github.com/google/gopacket),  
  [libpcap](https://www.tcpdump.org/), [Npcap](https://npcap.com/),  
  [tview](https://github.com/rivo/tview), etc.)
- Issues that require a compromised host or elevated OS privileges
  the attacker already possesses
- Social engineering against maintainers
- Denial of service via resource exhaustion on a machine you already control
- Missing security headers on unrelated websites

---

## Threat Model

NetSentinel is a **privileged network analysis tool**. It runs with raw
socket access (typically via `CAP_NET_RAW` or `sudo`) and processes
untrusted packets from the wire. Known assumptions:

- **Input is hostile.** Every parsed packet is untrusted. Parsers must
  not panic, overflow, or allocate unbounded memory on malformed input.
- **Users are trusted.** The person running NetSentinel is assumed to
  have administrative intent. We do not defend against a user attacking
  their own machine.
- **Plugins are trusted.** Dynamically loaded plugins run in-process with
  full privileges. Only load plugins you trust.
- **Reports may contain sensitive data.** Captured payloads, IPs and
  credentials can end up in reports. Handle output files accordingly.

### Specific areas of concern

| Area | Concern |
| --- | --- |
| Packet parser | Malformed packets causing panics or OOM |
| BPF filter handling | Filter injection or crashes on crafted filters |
| Report writers | Path traversal via output flags |
| Plugin loader | Arbitrary code execution if plugin path is attacker-controlled |
| CI workflows | Secret leakage, cache poisoning, dependency confusion |

If you find an issue in any of these areas, we especially want to hear
about it.

---

## Hardening Recommendations for Users

- Run NetSentinel with `CAP_NET_RAW,cap_net_admin` via `setcap` instead
  of full `sudo` where possible.
- Never load plugins from untrusted sources.
- Treat generated `.json` / `.html` reports as sensitive — they contain
  packet metadata and potentially payload data.
- Keep libpcap / Npcap updated.
- Prefer building from a tagged release over running arbitrary branches.

---

## Acknowledgements

We are grateful to the security researchers who help keep NetSentinel
and its users safe. Reporters who wish to be credited will be listed
here after disclosure.

---

## Contact

For non-security questions, please use GitHub Issues or Discussions.
For security matters, use the private channels above.