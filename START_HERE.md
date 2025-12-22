# ✅ Ready to Use!

The command is now: **`sniff`**

## Quick Start

### 1. Find your interface:
```bash
ifconfig
```
Look for **en0** or **wlan0** with an IP address.

### 2. Find your IP:
```bash
ifconfig en0 | grep "inet " | awk '{print $2}'
```

### 3. Start sniffing!

#### See EVERYTHING (like Wireshark):
```bash
sudo sniff live --iface en0 --show-all
```

#### See only YOUR traffic:
```bash
# Replace with YOUR IP from step 2
sudo sniff live --iface en0 --device 10.101.7.164 --show-all
```

#### Security monitoring (quiet):
```bash
sudo sniff live --iface en0 --alerts-only
```

### 4. Stop capture:
Press **Ctrl+C**

---

## All Available Modes:

```bash
# 1. SHOW ALL MODE (like Wireshark)
sudo sniff live --iface en0 --show-all

# 2. FILTER YOUR DEVICE
sudo sniff live --iface en0 --device YOUR_IP --show-all

# 3. SECURITY MODE (default - only alerts)
sudo sniff live --iface en0

# 4. ALERTS ONLY (very quiet)
sudo sniff live --iface en0 --alerts-only

# 5. VERBOSE MODE (detailed info)
sudo sniff live --iface en0 --verbose
```

---

## Example Session:

```bash
# Get your IP
$ ifconfig en0 | grep "inet " | awk '{print $2}'
10.101.7.164

# Start monitoring YOUR traffic
$ sudo sniff live --iface en0 --device 10.101.7.164 --show-all

# Output:
[DNS] 10.101.7.164 → google.com
[HTTPS] 10.101.7.164 → google.com:443
[TCP] 10.101.7.164:54321 → 142.250.73.131:443
[DNS] 10.101.7.164 → youtube.com
[HTTPS] 10.101.7.164 → youtube.com:443
...

# Press Ctrl+C to stop

============================================================
Websites Visited:
============================================================

Device: 10.101.7.164
  Websites visited:
    1. google.com
    2. youtube.com

============================================================
Capture Summary:
  Packets processed: 547
  Duration: 45.2 seconds
============================================================
```

---

## Help Commands:

```bash
sniff --help              # Main help
sniff live --help         # Live capture help
sniff pcap --help         # PCAP analysis help
```

---

## Documentation:

- **COMMAND_REFERENCE.md** - Complete command reference
- **MODES.md** - Detailed mode explanations
- **TROUBLESHOOTING.md** - If something doesn't work
- **README.md** - Full documentation

---

## You're All Set! 🎉

Just run:
```bash
sudo sniff live --iface en0 --show-all
```

And you'll see all network traffic immediately!
