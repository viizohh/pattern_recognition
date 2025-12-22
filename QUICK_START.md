# net-watch Quick Start

## Pick Your Mode:

```bash
# 🔒 SECURITY MODE (default)
# Shows: Only suspicious behavior
sudo net-watch live --iface en0

# 👁️ SHOW ALL MODE (like Wireshark)
# Shows: EVERY connection, DNS query, MDNS announcement
sudo net-watch live --iface en0 --show-all

# 🎯 FILTER YOUR DEVICE
# Shows: Only YOUR traffic (on busy network)
sudo net-watch live --iface en0 --device YOUR_IP --show-all

# 🔕 QUIET MODE
# Shows: Only warnings and alerts
sudo net-watch live --iface en0 --alerts-only

# 📊 VERBOSE MODE
# Shows: Technical details and context
sudo net-watch live --iface en0 --verbose
```

## Stop Capture
Press **Ctrl+C**

## Find Your Info

### Find your network interface:
```bash
ifconfig
# Look for "en0" or "wlan0" that has an IP
```

### Find your IP:
```bash
ifconfig | grep "inet " | grep -v 127.0.0.1
# Or just use ifconfig and look for your local IP (10.x.x.x or 192.168.x.x)
```

## Full Help
```bash
net-watch --help
net-watch live --help
net-watch pcap --help
```

## Examples

### See everything on your network:
```bash
sudo net-watch live --iface en0 --show-all
```

### Monitor just YOUR device:
```bash
sudo net-watch live --iface en0 --device 10.101.7.164 --show-all
```

### Security monitoring (quiet):
```bash
sudo net-watch live --iface en0 --alerts-only
```

### Understand a website's tracking:
```bash
sudo net-watch live --iface en0 --device YOUR_IP
# Visit linkedin.com
# Press Ctrl+C
# See how many trackers it loaded!
```

---

See **MODES.md** for detailed explanation of each mode!
