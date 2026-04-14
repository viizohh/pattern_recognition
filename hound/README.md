# Hound - Network Traffic Analyzer

A standalone network traffic analyzer that monitors and analyzes network traffic in real-time.

## Features

- **Live Traffic Capture**: Monitor network traffic in real-time on any interface
- **PCAP Analysis**: Analyze saved packet capture files
- **Protocol Parsing**: Extract information from DNS, HTTP/HTTPS, and TCP packets
- **Device Tracking**: Monitor all devices on your network
- **Connection Tracking**: Track TCP connections and data transfer
- **Behavior Detection**:
  - Beaconing detection (periodic automated communication)
  - Tracking detection (third-party tracking cookies)
  - Anomaly detection (DGA domains, port scanning, etc.)
- **Session Tracking**: Track website browsing sessions with context

## Installation

```bash
cd hound
pip install -e .
```

## Usage

Start the interactive shell:

```bash
hound
```

### Available Commands

Once in the hound shell, use these commands:

**Sniff live traffic:**
```bash
sniff live --iface en0 --show-all
```

**Analyze PCAP file:**
```bash
sniff pcap capture.pcap --show-all
```

**Filter for specific device:**
```bash
sniff live --iface en0 --device 10.101.7.164
```

### Options

- `--iface TEXT`: Network interface (required for live capture)
- `--device TEXT`: Filter for specific device IP
- `--show-all`: Show ALL traffic (like Wireshark)
- `--alerts-only`: Only show warnings and alerts
- `--verbose`: Show detailed information

## Requirements

- Python 3.8+
- scapy >= 2.5.0
- click >= 8.1.0
- colorama >= 0.4.6
- tabulate >= 0.9.0
- python-dateutil >= 2.8.2

## Permissions

Network packet capture requires elevated privileges:

- **macOS**: Run with `sudo`
- **Linux**: Run with `sudo` or grant capabilities to Python
- **Windows**: Run as Administrator

## Example

```bash
$ hound
hound> sniff live --iface en0 --show-all
# Start monitoring network traffic...
```

## License

See LICENSE file for details.
