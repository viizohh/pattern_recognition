# Installation Guide

## Quick Start

### 1. Create a Virtual Environment (Recommended)

```bash
cd hound
python3 -m venv venv
source venv/bin/activate
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Install Hound

```bash
pip install -e .
```

### 4. Run Hound

```bash
# On macOS/Linux, you'll need sudo for packet capture
sudo hound

# Or run directly with the virtual environment
sudo venv/bin/python -m net_watch.cli
```

## What's Included

The standalone hound directory contains only the network traffic analyzer component:

### Core Modules
- **capture.py**: Packet capture engine (live and PCAP)
- **cli.py**: Command-line interface and network monitor orchestrator
- **shell.py**: Interactive shell (without OSINT/breach features)

### Protocol Parsers
- **parsers/dns.py**: DNS query/response parsing
- **parsers/http.py**: HTTP/HTTPS connection parsing
- **parsers/tcp.py**: TCP connection parsing

### Trackers
- **tracking/device_tracker.py**: Track devices on network
- **tracking/domain_tracker.py**: Track domain access patterns
- **tracking/connection_tracker.py**: Track TCP connections
- **tracking/session_tracker.py**: Track browsing sessions

### Detectors
- **detectors/beaconing.py**: Detect periodic automated communication
- **detectors/tracking.py**: Detect third-party tracking
- **detectors/anomaly.py**: Detect anomalies (DGA, port scanning, etc.)

### Utilities
- **filters.py**: Network traffic filters
- **utils.py**: Utility functions
- **alerts.py**: Alert management system

## Usage Examples

Once installed, run `hound` to enter the interactive shell:

```bash
$ sudo hound
hound> sniff live --iface en0 --show-all
```

### Common Commands

**Capture live traffic on interface en0:**
```
sniff live --iface en0
```

**Capture with verbose output:**
```
sniff live --iface en0 --verbose
```

**Filter for specific device:**
```
sniff live --iface en0 --device 192.168.1.100
```

**Analyze PCAP file:**
```
sniff pcap capture.pcap --show-all
```

## Troubleshooting

### Permission Denied
Packet capture requires elevated privileges. Run with `sudo` on Unix systems or as Administrator on Windows.

### Module Not Found
Make sure you've activated the virtual environment and installed dependencies:
```bash
source venv/bin/activate
pip install -r requirements.txt
```

### Interface Not Found
List available network interfaces:
```bash
# macOS
ifconfig

# Linux
ip link show
```

Common interface names:
- macOS: `en0` (WiFi), `en1` (Ethernet)
- Linux: `eth0`, `wlan0`
- Windows: Use full interface name from `ipconfig`
