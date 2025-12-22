# sniff - Command Reference

## Quick Commands

```bash
# Show everything (like Wireshark)
sudo sniff live --iface en0 --show-all

# Show only YOUR traffic
sudo sniff live --iface en0 --device YOUR_IP --show-all

# Security monitoring (default)
sudo sniff live --iface en0

# Only warnings/alerts
sudo sniff live --iface en0 --alerts-only

# Verbose mode with details
sudo sniff live --iface en0 --verbose

# Analyze a pcap file
sniff pcap capture.pcap --show-all
```

## Command Syntax

```
sniff [OPTIONS] COMMAND [ARGS]
```

### Commands:
- `live` - Start live packet capture
- `pcap` - Analyze a pcap file

### Global Options:
- `--version` - Show version
- `--help` - Show help

## Live Capture Options

```bash
sniff live --iface INTERFACE [OPTIONS]
```

### Required:
- `--iface TEXT` - Network interface (e.g., en0, wlan0)

### Optional:
- `--show-all` - Show ALL traffic (like Wireshark)
- `--device IP` - Filter for specific device IP
- `--verbose` - Show detailed technical information
- `--alerts-only` - Only show warnings and alerts
- `--help` - Show help for this command

## PCAP Analysis Options

```bash
sniff pcap FILE [OPTIONS]
```

### Required:
- `FILE` - Path to pcap file

### Optional:
- `--show-all` - Show ALL traffic
- `--device IP` - Filter for specific device IP
- `--verbose` - Show detailed information
- `--alerts-only` - Only show warnings and alerts
- `--help` - Show help for this command

## Examples

### Basic Usage

```bash
# List your interfaces
ifconfig

# Start capturing (replace en0 with your interface)
sudo sniff live --iface en0 --show-all
```

### See Your Traffic Only

```bash
# Get your IP
ifconfig en0 | grep "inet " | awk '{print $2}'

# Capture (replace 10.101.7.164 with your IP)
sudo sniff live --iface en0 --device 10.101.7.164 --show-all
```

### Security Monitoring

```bash
# Default - only show suspicious behavior
sudo sniff live --iface en0

# Quiet - only warnings and alerts
sudo sniff live --iface en0 --alerts-only
```

### Analysis

```bash
# Analyze a pcap file
sniff pcap network_capture.pcap --show-all

# Analyze with verbose output
sniff pcap network_capture.pcap --verbose
```

## Stop Capture

Press **Ctrl+C** to stop any running capture.

You'll see:
- Websites visited summary
- Alert statistics
- Packet count and duration

## Mode Comparison

| Command | What It Shows | Noise Level |
|---------|--------------|-------------|
| `sudo sniff live --iface en0` | Security alerts only | Low |
| `sudo sniff live --iface en0 --show-all` | Everything | Very High |
| `sudo sniff live --iface en0 --alerts-only` | Warnings+ only | Very Low |
| `sudo sniff live --iface en0 --verbose` | Alerts + details | Medium |
| `sudo sniff live --iface en0 --device IP --show-all` | One device, all traffic | Medium |

## Getting Help

```bash
# Main help
sniff --help

# Help for live capture
sniff live --help

# Help for pcap analysis
sniff pcap --help
```

## Common Issues

### "Permission denied"
Run with sudo:
```bash
sudo sniff live --iface en0
```

### "No such device"
Check your interface name:
```bash
ifconfig
# Look for en0, wlan0, etc.
```

### "No traffic showing"
1. Make sure you're using the right interface
2. Generate traffic (visit websites)
3. Try without --device filter first
4. See TROUBLESHOOTING.md

## Documentation

- **README.md** - Full documentation
- **MODES.md** - Detailed explanation of modes
- **QUICK_START.md** - Quick reference
- **TROUBLESHOOTING.md** - Problem solving
- **WEBSITE_TRACKING.md** - Website tracking feature
