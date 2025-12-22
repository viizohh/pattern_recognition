# 🐕 hound - Network Monitoring Tool

**Application Name:** hound
**Command:** `sniff`
**Version:** 0.1.0

---

## Quick Start

```bash
# Show everything (like Wireshark)
sudo sniff live --iface en0 --show-all

# Show only YOUR traffic
sudo sniff live --iface en0 --device YOUR_IP --show-all

# Security monitoring (quiet)
sudo sniff live --iface en0 --alerts-only

# Get help
sniff --help
```

---

## What is hound?

**hound** is a command-line network monitoring tool that:
- 📡 Captures network traffic in real-time
- 🔍 Detects suspicious behavior (beaconing, tracking, anomalies)
- 📝 Explains network activity in plain English
- 🎯 Filters traffic by device or shows everything
- 🚨 Alerts on security concerns

---

## All Available Modes

| Command | What You See |
|---------|-------------|
| `sudo sniff live --iface en0 --show-all` | **Everything** (like Wireshark) |
| `sudo sniff live --iface en0 --device IP --show-all` | **Your device only** |
| `sudo sniff live --iface en0` | **Security alerts only** |
| `sudo sniff live --iface en0 --alerts-only` | **Warnings/alerts only** |
| `sudo sniff live --iface en0 --verbose` | **Detailed info** |

---

## Example Usage

### See All Network Traffic:
```bash
sudo sniff live --iface en0 --show-all
```

**Output:**
```
hound v0.1.0 - Live Network Monitor
============================================================

Starting live capture on en0...
Press Ctrl+C to stop

[mDNS] 10.101.7.109 → Fawaz's Iphone ._rdlink._tcp.local
[DNS] 10.101.7.164 → google.com
[HTTPS] 10.101.7.164 → google.com:443
[TCP] 10.101.6.29:52341 → 142.250.31.95:443
[ARP] Who has 10.101.5.162? Tell 10.101.6.121
...
```

### Monitor Just YOUR Traffic:
```bash
# Get your IP
ifconfig en0 | grep "inet " | awk '{print $2}'

# Monitor it (replace with your IP)
sudo sniff live --iface en0 --device 10.101.7.164 --show-all
```

**Output:**
```
[DNS] 10.101.7.164 → youtube.com
[HTTPS] 10.101.7.164 → youtube.com:443
[DNS] 10.101.7.164 → googlevideo.com
[TCP] 10.101.7.164:54321 → 142.250.73.131:443
```

### Security Monitoring (Quiet):
```bash
sudo sniff live --iface en0
```

**Output:**
```
... quiet unless suspicious activity detected ...

[ALERT] Device contacted suspicious-domain.com every 60 seconds
        → Behavior matches automated beaconing patterns.

[WARNING] Repeated failed connections to 203.0.113.50:22
        → Multiple connection failures could indicate scanning.
```

---

## Features

### 🔒 Security Detection
- **Beaconing**: Periodic C2-like communication
- **Tracking**: Excessive third-party analytics
- **Anomalies**: Port scanning, failed connections, DGA domains
- **Long connections**: Idle encrypted connections

### 👁️ Traffic Analysis
- DNS query/response tracking
- HTTP/HTTPS connection monitoring
- TCP/UDP packet analysis
- Per-device statistics
- Website tracking

### 📊 Output Modes
- **Show all**: Every packet (like Wireshark)
- **Security mode**: Only suspicious behavior
- **Alerts only**: Warnings and alerts
- **Verbose**: Technical details
- **Device filter**: One device only

---

## Installation

```bash
cd /Users/h/ClaudeAssignments/Packets
pip install -r requirements.txt
pip install -e .
```

---

## Commands

### Live Capture:
```bash
sniff live --iface INTERFACE [OPTIONS]
```

**Options:**
- `--show-all` - Show ALL traffic
- `--device IP` - Filter for specific device
- `--verbose` - Detailed information
- `--alerts-only` - Only warnings/alerts

### PCAP Analysis:
```bash
sniff pcap FILE [OPTIONS]
```

**Options:**
- `--show-all` - Show ALL traffic
- `--device IP` - Filter for specific device
- `--verbose` - Detailed information

### Help:
```bash
sniff --help              # Main help
sniff live --help         # Live capture help
sniff pcap --help         # PCAP analysis help
```

---

## Documentation

- **START_HERE.md** - Quick start guide
- **COMMAND_REFERENCE.md** - Complete command reference
- **MODES.md** - Detailed mode explanations
- **TROUBLESHOOTING.md** - Problem solving
- **README.md** - Full documentation

---

## Requirements

- Python 3.8+
- Root/sudo access (for packet capture)
- macOS, Linux, or BSD

---

## Stopping Capture

Press **Ctrl+C** to stop.

You'll see:
- Websites visited summary
- Alert statistics
- Packet count and duration

---

## Example Session

```bash
$ sudo sniff live --iface en0 --device 10.101.7.164 --show-all

hound v0.1.0 - Live Network Monitor
============================================================

Starting live capture on en0...
Filtering for device: 10.101.7.164
Press Ctrl+C to stop

[DNS] 10.101.7.164 → linkedin.com
[HTTPS] 10.101.7.164 → linkedin.com:443
[DNS] 10.101.7.164 → platform.linkedin.com
[HTTPS] 10.101.7.164 → platform.linkedin.com:443

[INFO] Device made 23 connections to 8 third-party domains while visiting linkedin.com.
        → Common tracking behavior, low risk.

^C
============================================================
Websites Visited:
============================================================

Device: 10.101.7.164
  Websites visited:
    1. linkedin.com

============================================================
Capture Summary:
  Packets processed: 234
  Duration: 15.4 seconds
  Rate: 15.2 packets/sec

Alerts:
  INFO: 1
============================================================
```

---

## 🐕 hound is ready to sniff your network!

Use `sniff --help` for more information.
