# net-watch Usage Modes

Now you can choose exactly what you want to see! Here are all the different modes:

## Quick Reference

```bash
# 1. SECURITY MODE (default) - Only show suspicious behavior
sudo net-watch live --iface en0

# 2. SHOW ALL MODE - See everything like Wireshark
sudo net-watch live --iface en0 --show-all

# 3. ALERTS ONLY - Just warnings/alerts, no info
sudo net-watch live --iface en0 --alerts-only

# 4. VERBOSE MODE - Detailed technical info
sudo net-watch live --iface en0 --verbose

# 5. FILTER BY DEVICE - Focus on one device
sudo net-watch live --iface en0 --device 10.101.7.164

# 6. COMBINE MODES - Mix and match!
sudo net-watch live --iface en0 --device 10.101.7.164 --show-all
```

---

## Mode 1: Security Monitoring (DEFAULT)

**What it does:** Only shows **suspicious behavior** and security alerts

```bash
sudo net-watch live --iface en0
```

**You'll see:**
- ✅ Beaconing patterns (periodic C2-like traffic)
- ✅ Excessive tracking
- ✅ Port scanning
- ✅ Failed connection attempts
- ✅ Anomalies

**You WON'T see:**
- ❌ Normal MDNS/Bonjour announcements
- ❌ ARP broadcasts
- ❌ Background OS services
- ❌ Regular web browsing

**Best for:** Daily security monitoring, finding threats

**Example output:**
```
[ALERT] Device contacted suspicious-domain.com every 60 seconds for 2 hours.
        → Behavior matches automated beaconing patterns.

[WARNING] Repeated failed connections to 203.0.113.50:22 (15 attempts).
        → Multiple connection failures could indicate scanning activity.
```

---

## Mode 2: Show ALL Traffic (NEW!)

**What it does:** Displays **EVERY connection** like Wireshark

```bash
sudo net-watch live --iface en0 --show-all
```

**You'll see:**
- ✅ Every DNS query
- ✅ Every HTTP request
- ✅ Every HTTPS connection
- ✅ MDNS announcements
- ✅ All device traffic
- ✅ **Everything!**

**Best for:** Understanding all network activity, debugging, learning

**Example output:**
```
[mDNS] 10.101.7.109 → Fawaz's Iphone ._rdlink._tcp.local
[DNS] 10.101.7.164 → linkedin.com
[HTTPS] 10.101.7.164 → linkedin.com:443
[mDNS] 10.101.5.237 → Android-2._FC9F5ED42C8A._tcp.local
[DNS] 10.101.7.164 → platform.linkedin.com
[HTTPS] 10.101.7.164 → platform.linkedin.com:443
[TCP] 10.101.6.29 → 142.250.31.95:443 (encrypted)
... 100+ lines per second ...

[ALERT] Device contacted api.tracker.com every 60 seconds
        → Behavior matches automated beaconing patterns.
```

---

## Mode 3: Alerts Only

**What it does:** Shows **only warnings and alerts**, hides INFO messages

```bash
sudo net-watch live --iface en0 --alerts-only
```

**You'll see:**
- ✅ WARNING level alerts
- ✅ ALERT level alerts
- ✅ CRITICAL alerts

**You WON'T see:**
- ❌ INFO messages (normal tracking, etc.)

**Best for:** Monitoring without noise, focus on problems only

**Example output:**
```
[WARNING] Repeated failed connections to 151.101.195.52:443 (18 attempts).
        → Multiple connection failures could indicate a network issue.

[ALERT] Domain 'asdkfjh234lkj.com' has unusually high randomness (entropy: 5.2).
        → High entropy domains can indicate DGA malware.
```

---

## Mode 4: Verbose Mode

**What it does:** Shows **technical details** and context

```bash
sudo net-watch live --iface en0 --verbose
```

**You'll see:**
- ✅ Website context for traffic
- ✅ Technical details in alerts
- ✅ DNS resolution info

**Example output:**
```
DNS: linkedin.com (new visit)
DNS: platform.linkedin.com (while visiting linkedin.com)
DNS: static.licdn.com (while visiting linkedin.com)

[INFO] Device made 45 connections to 12 third-party domains while visiting linkedin.com.
        → Common tracking behavior, low risk.

Technical Details:
  Entropy: 4.23, Queries: 15, Interval: 120.5s
```

---

## Mode 5: Filter by Device

**What it does:** Shows traffic **only from/to a specific device**

```bash
# Find your IP first
ifconfig | grep "inet "

# Then filter for it (replace with your IP)
sudo net-watch live --iface en0 --device 10.101.7.164
```

**You'll see:**
- ✅ Only traffic involving 10.101.7.164
- ✅ Ignore all other devices

**Best for:** Monitoring YOUR traffic on a busy network (school, office, public WiFi)

**Example output:**
```
[INFO] Device 10.101.7.164 made 23 connections while visiting youtube.com.
        → Common tracking behavior, low risk.

[DNS] 10.101.7.164 → googlevideo.com
[HTTPS] 10.101.7.164 → googlevideo.com:443
```

---

## Mode 6: Combine Modes!

**Mix and match flags** to get exactly what you want:

### See ALL traffic from YOUR device only:
```bash
sudo net-watch live --iface en0 --device 10.101.7.164 --show-all
```

Shows every packet from/to your device, nothing else.

### See ALL traffic but only show alerts:
```bash
sudo net-watch live --iface en0 --show-all --alerts-only
```

Shows all connections PLUS security alerts (no INFO messages).

### Your device + verbose details:
```bash
sudo net-watch live --iface en0 --device 10.101.7.164 --verbose
```

Detailed info about YOUR traffic only.

### Everything with full details:
```bash
sudo net-watch live --iface en0 --show-all --verbose
```

Every packet + technical details (VERY noisy!).

---

## Comparison Table

| Mode | Shows Traffic | Shows Alerts | Noise Level | Best For |
|------|--------------|--------------|-------------|----------|
| **Default** | ❌ No | ✅ All | Low | Security monitoring |
| **--show-all** | ✅ All | ✅ All | Very High | Understanding everything |
| **--alerts-only** | ❌ No | ⚠️ Warnings+ only | Very Low | Quiet monitoring |
| **--verbose** | ❌ No | ✅ All + details | Medium | Detailed analysis |
| **--device IP** | ✅ One device | ✅ That device | Low-Medium | Personal monitoring |
| **--show-all --device IP** | ✅ One device | ✅ All | Medium | Your traffic only |

---

## Real-World Examples

### 1. Daily Security Monitoring
```bash
sudo net-watch live --iface en0 --alerts-only
```
Run in the background, only shows real problems.

### 2. Debugging Network Issues
```bash
sudo net-watch live --iface en0 --show-all --device 10.101.7.164
```
See every connection from your device.

### 3. Understanding a Website's Tracking
```bash
sudo net-watch live --iface en0 --device 10.101.7.164
# Visit the website
# Press Ctrl+C
# See how many trackers it loaded!
```

### 4. Learning Network Behavior
```bash
sudo net-watch live --iface en0 --show-all
```
See everything happening on your network.

### 5. Finding What's Using Bandwidth
```bash
sudo net-watch live --iface en0 --show-all
```
Watch which devices are making tons of connections.

---

## Tips

1. **Start simple:** Use default mode first
2. **Too noisy?** Add `--alerts-only`
3. **Too quiet?** Add `--show-all`
4. **Busy network?** Add `--device YOUR_IP`
5. **Want details?** Add `--verbose`

## Stop Capture

All modes: Press **Ctrl+C**

You'll see:
- Summary of websites visited
- Alert statistics
- Packet count and duration

---

Now you have **complete control** over what net-watch shows you!
