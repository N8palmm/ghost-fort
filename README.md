# 🛡️ Ghost Fort — Personal Blue Team Security Stack

A multi-layered, automated cybersecurity defense system built on WSL2 Ubuntu running on Windows. Designed around **defense in depth** — every layer operates independently so if one fails, the next holds.

## Architecture

| Layer | Component | Function |
|---|---|---|
| 1 | VPN (Malwarebytes) | Outbound encryption |
| 2 | IDS Engine | Inbound threat detection |
| 3 | iptables/nftables | Kernel-level firewall |
| 4 | fail2ban | Brute force protection |
| 5 | Browser Hardening | Fingerprint/tracking protection |
| 6 | Identity Shield | Data broker monitoring |
| 7 | Phone Monitor | SIM swap protection |
| 8 | Credit Freeze Manager | Bureau freeze tracking |

## Core Components

- **intel_engine.py** — Aggregates 9 live threat intel feeds, 570,000+ malicious IPs
- **ids_engine.py** — Behavioral IDS detecting port scans, SSH brute force, RDP attacks
- **alert_notifier.py** — Real-time Discord alerts with geolocation enrichment
# 🛡️ Ghost Fort — Personal Cybersecurity Defense Stack

> **Defense in depth, automated. Every layer operates independently — if one fails, the next holds.**

Built and maintained by a U.S. Air Force veteran and enterprise IT professional. Ghost Fort is a fully operational, multi-layered personal cybersecurity defense system running on WSL2 Ubuntu alongside Windows. This is not a tutorial project or a proof of concept — it is a live, production system that runs continuously, pulls real threat intelligence, and actively defends against inbound threats.

---

## 🏗️ Architecture Overview

Ghost Fort implements eight independent layers of defense, each purpose-built and operating autonomously:

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1 — VPN (Malwarebytes)                           │
│  Outbound encryption, IP masking, DNS leak protection   │
├─────────────────────────────────────────────────────────┤
│  Layer 2 — Ghost IDS Engine                             │
│  Real-time behavioral intrusion detection, auto-ban     │
├─────────────────────────────────────────────────────────┤
│  Layer 3 — iptables / nftables Firewall                 │
│  Kernel-level packet filtering, custom GHOST_IDS chain  │
├─────────────────────────────────────────────────────────┤
│  Layer 4 — fail2ban                                     │
│  Brute force protection integrated with IDS logs        │
├─────────────────────────────────────────────────────────┤
│  Layer 5 — Browser Hardening                            │
│  Brave + Firefox, WebRTC/canvas/fingerprint blocking    │
├─────────────────────────────────────────────────────────┤
│  Layer 6 — Identity Shield                              │
│  50+ data broker monitoring, breach detection           │
├─────────────────────────────────────────────────────────┤
│  Layer 7 — Phone Monitor                                │
│  SIM swap protection, reverse lookup opt-outs           │
├─────────────────────────────────────────────────────────┤
│  Layer 8 — Credit Freeze Manager                        │
│  Active freeze tracking across all 8 major bureaus      │
└─────────────────────────────────────────────────────────┘
```

---

## ⚙️ Core Components

### `intel_engine.py` — Threat Intelligence Pipeline

The engine aggregates **9 live threat intelligence feeds** and maintains a local database of **570,000+ known malicious IPs**:

| Feed | Type |
|---|---|
| FireHOL Level 1 | High-confidence malicious IPs |
| FireHOL Level 2 | Expanded threat list |
| Spamhaus DROP | Don't Route Or Peer list |
| Spamhaus EDROP | Extended DROP |
| Emerging Threats Botnet | Active botnet C2 infrastructure |
| Emerging Threats Compromised | Known compromised hosts |
| Bruteforce Blocklist | Active brute force sources |
| Tor Exit Nodes | Anonymization infrastructure |
| IPsum | Aggregated threat data |

**Technical implementation:**
- SQLite database with in-memory index for sub-millisecond IP lookups
- CIDR range matching — blocks entire malicious subnets, not just single IPs
- Hash-based deduplication — no redundant entries across feeds
- Feed content validation — rejects feeds that return suspiciously sparse data
- Automatic refresh on configurable schedule with no manual intervention

---

### `ids_engine.py` — Behavioral Intrusion Detection System

Real-time monitoring of every inbound network connection with behavioral analysis:

**Detection rules:**
- **Port scan detection** — flags any source hitting 10+ ports within 60 seconds
- **SSH brute force detection** — triggers on 15+ failed attempts within 60 seconds
- **RDP attack detection** — monitors Remote Desktop attack patterns
- **Connection flood detection** — identifies denial-of-service behavior

**Architecture:**
- Three-tier monitoring fallback chain: `nftables → journald → dmesg → netstat`
- Passive OS fingerprinting from TCP headers — identifies attacker's operating system
- CDN whitelist (Cloudflare, Fastly, Akamai) — eliminates false positives from legitimate CDN traffic
- Privileged/unprivileged process split via Unix socket for security isolation
- Watchdog thread monitors all daemon threads and alerts if any die

**Auto-response:**
Detected threats are automatically added to the `GHOST_IDS` iptables ban chain. No manual intervention required.

---

### `alert_notifier.py` — Real-Time Alert System

Every detected threat generates a Discord webhook alert containing a full attacker profile:

```
🚨 THREAT DETECTED
IP: 185.220.101.47
Reason: SSH Brute Force (47 attempts/60s)
Risk Level: CRITICAL
Country: Russia (RU) | Region: Moscow Oblast
ISP: Frantech Solutions | ASN: AS59930
OS Fingerprint: Linux 3.x / 4.x
Ports Probed: 22, 2222, 2022
Feed Match: firehol_level1, emerging_threats_botnet
```

**Technical implementation:**
- Secrets managed via system keyring — zero plaintext credentials in codebase
- Retry logic with exponential backoff for reliability
- Geolocation enrichment via intel_engine caching layer (HTTPS, rate-limited)

---

### `ghost_dashboard_server.py` — Security Operations Dashboard

Flask web server providing a live view into Ghost Fort's operational status:

- **Total blocked IPs** — running count of all auto-bans
- **Active bans** — currently enforced blocks with timestamps
- **Threat intel DB size** — feed health indicator
- **Recent blocks** — full attacker profiles for last N detections
- Auto-refreshes every 10 seconds
- Locked to `localhost` only via iptables — zero external exposure

---

### `identity_shield.py` — Identity Protection Module

- Scans **50+ data broker websites** for personal information exposure
- Checks email addresses against **HaveIBeenPwned** breach database
- Generates legally compliant **CCPA/VCDPA opt-out removal requests**
- Google exposure scanning with removal request generation
- **Auto-rescans every 30 days** with Discord alerts on new exposures

---

### `ghost_dns_monitor.py` — Privacy Leak Monitor

Continuously monitors external IP, DNS servers, and IPv6 exposure. Alerts immediately via Discord if any privacy leak is detected.

---

### `ghost_health_check.py` — Automated Maintenance

Quarterly automated health checks via systemd timer (every 90 days):
- Validates all services are running
- Checks database integrity
- Monitors disk space
- Verifies firewall rules are intact
- Confirms IPv6 is blocked
- Validates DNS integrity
- Updates Python dependencies and system packages automatically
- Sends full health report to Discord

---

### `phone_monitor.py` — Phone Number Protection

- Scans **16 reverse phone lookup and spam databases**
- Generates carrier-specific **SIM lock instructions** for SIM swap protection
- Opt-out request generation for all broker platforms
- Auto-rescans every 30 days

---

### `credit_freeze.py` — Credit Bureau Freeze Manager

Tracks credit freeze status across all 8 major bureaus:

| Bureau |
|---|
| Equifax |
| Experian |
| TransUnion |
| ChexSystems |
| Innovis |
| NCTUE |
| LexisNexis |
| SageStream |

Features: step-by-step freeze guides with direct URLs, secure PIN hint storage, temporary lift tracking with Discord reminders, expired lift alerts.

---

## 🌐 Browser Hardening

### Brave (Primary)
- WebRTC disabled at **Windows registry level** (system policy — not just browser settings)
- Canvas fingerprinting randomized via Canvas Blocker
- Strict tracker and ad blocking
- HTTPS strict mode enforced
- Third-party cookies blocked
- Facebook/Twitter/LinkedIn embeds blocked
- Forget-me-on-close enabled
- uBlock Origin + Malwarebytes Browser Guard

### Firefox (Secondary)
- **arkenfox `user.js`** applied — hardened configuration
- WebRTC completely disabled
- Canvas and font fingerprinting blocked
- All telemetry disabled
- Google Safe Browsing removed
- DNS over HTTPS enforced
- HTTPS-only mode
- History and cache disabled
- WebGL disabled
- Multi-Account Containers for identity isolation

---

## 🖥️ Infrastructure

### Systemd Services

| Service | Function |
|---|---|
| `ghost-fort.service` | Main orchestrator — threat intel + IDS |
| `ghost-dashboard.service` | Web dashboard server |
| `ghost-identity.service` | Identity shield monitor |
| `ghost-health.timer` | Quarterly maintenance timer |

### iptables Chains

| Chain | Function |
|---|---|
| `GHOST_IDS` | Auto-ban chain for detected threats |
| `GHOST_KILLSWITCH` | Emergency network kill switch |

### Network Security
- **IPv6 fully disabled** via ip6tables, persisted across reboots
- **fail2ban** integrated with Ghost Fort IDS logs
- **DNS** forced through VPN tunnel — no ISP DNS exposure

### Windows Integration
- **Scheduled Task** (`GhostFort`) starts WSL2 and all services silently on Windows login
- **System Tray App** (`ghost_tray.py`) — shield icon with green/red status indicator, click to open dashboard

---

## 🗄️ Databases

| Database | Contents |
|---|---|
| `threat_intel.db` | 570,000+ malicious IPs, blocked IPs, feed status |
| `identity.db` | Broker exposures, breach results, removal requests |
| `phone.db` | Phone number exposures, removal requests |
| `credit.db` | Freeze status across all 8 bureaus, temp lifts |

---

## ✅ Security Audit Results

| Test | Result |
|---|---|
| WebRTC leak test | ✅ No leak |
| Canvas fingerprint | ✅ Randomized every session |
| DNS leak test | ✅ VPN DNS only |
| IPv6 exposure | ✅ Blocked confirmed |
| External IP | ✅ VPN only |
| ipleak.net full test | ✅ Clean |

---

## 📊 SIEM Integration

Ghost Fort journal logs are ingested into **Splunk** for real-time monitoring, threat correlation, and automated alerting. Splunk dashboards track feed health, error rates, and blocked IP trends over time. Custom SPL queries correlate Ghost Fort IDS events with threat intel feed data to identify attack patterns.

---

## 🚀 Deployment

```bash
# WSL2 deployment
bash setup_wsl.sh

# Browser hardening (run as Administrator in PowerShell)
powershell -ExecutionPolicy Bypass -File ghost_browser_setup.ps1
```

---

## 🧠 Design Philosophy

Ghost Fort is built around one principle: **no single point of failure**.

- If the VPN fails, the IDS still detects and blocks threats
- If the IDS misses something, iptables auto-bans at the kernel level
- If the network is compromised, browser hardening prevents fingerprinting and tracking
- If credentials are leaked, the identity shield detects and initiates removal

Each layer assumes the others can be bypassed. This mirrors enterprise defense-in-depth architecture used in government and critical infrastructure environments.

---

## 🛠️ Tech Stack

`Python` `Bash` `SQLite` `Flask` `Splunk` `iptables` `nftables` `fail2ban` `systemd` `WSL2` `Ubuntu`
