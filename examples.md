# net-watch Examples

## Command Line Examples

### Basic Usage

Monitor your WiFi interface:
```bash
sudo net-watch live --iface wlan0
```

Monitor Ethernet:
```bash
sudo net-watch live --iface eth0
```

### Filtering

Monitor only traffic from/to a specific device:
```bash
sudo net-watch live --iface wlan0 --device 192.168.1.100
```

### Output Control

Show only warnings and alerts (hide informational messages):
```bash
sudo net-watch live --iface wlan0 --alerts-only
```

Show detailed technical information:
```bash
sudo net-watch live --iface wlan0 --verbose
```

Combine flags:
```bash
sudo net-watch live --iface wlan0 --device 192.168.1.50 --verbose --alerts-only
```

### PCAP Analysis

Analyze a captured network trace:
```bash
net-watch pcap network_capture.pcap
```

Analyze with verbose output:
```bash
net-watch pcap suspicious_traffic.pcap --verbose
```

Filter PCAP for specific device:
```bash
net-watch pcap home_network.pcap --device 192.168.1.25
```

## Creating Test PCAP Files

If you want to test net-watch with sample traffic, you can create PCAP files using tcpdump:

### Capture 100 packets:
```bash
sudo tcpdump -i wlan0 -c 100 -w test.pcap
```

### Capture for 60 seconds:
```bash
sudo timeout 60 tcpdump -i wlan0 -w test.pcap
```

### Capture only DNS traffic:
```bash
sudo tcpdump -i wlan0 port 53 -w dns.pcap
```

### Capture HTTP/HTTPS traffic:
```bash
sudo tcpdump -i wlan0 'port 80 or port 443' -w web.pcap
```

## Understanding the Output

### Alert Levels

**[INFO]** - Normal behavior, for your awareness
- Third-party tracking (common trackers like Google Analytics)
- General connection statistics
- Normal periodic updates

**[WARNING]** - Potentially concerning, worth investigating
- Unusual connection patterns
- Elevated failure rates
- Long-lived connections
- Suspicious port activity

**[ALERT]** - Suspicious behavior detected
- Unknown beaconing patterns
- High-entropy domains (potential DGA)
- Significant anomalies

**[CRITICAL]** - Highly suspicious, immediate attention recommended
- Reserved for severe security concerns

### Sample Output Interpretation

```
[ALERT] 2024-01-15 14:32:18
api.unknown-domain.com contacted every 60 seconds for 2 hours.
        → Behavior matches automated beaconing patterns.
```

**What this means:**
- A device on your network contacted the same domain repeatedly
- The interval is very regular (every 60 seconds)
- This continued for 2 hours
- Could be: legitimate service, update checker, or malware C2

**What to do:**
1. Identify which device is making the connections (check verbose output)
2. Research the domain name
3. Check what applications are running on that device
4. Consider blocking if suspicious

---

```
[WARNING] 2024-01-15 14:33:12
Device 192.168.1.105 has a long-lived connection to 203.0.113.50:443 (3 hours).
        → Connection has been open for extended period with minimal activity.
```

**What this means:**
- Device .105 has kept a connection open for 3 hours
- Port 443 = HTTPS (encrypted)
- Very little data being transferred

**What to do:**
1. Check what's running on device .105
2. Could be: SSH session, VPN, chat application, or persistent malware
3. Usually harmless but worth investigating

---

```
[INFO] 2024-01-15 14:32:45
Device made 143 connections to 27 third-party domains while visiting example.com.
        → Common tracking behavior, low risk.
```

**What this means:**
- While loading one website, the browser contacted 27 other domains
- These are tracking scripts, ads, analytics, social media widgets
- Very common on modern websites

**What to do:**
- This is normal for most websites
- Consider using an ad blocker for privacy
- No immediate security concern

## Real-World Scenarios

### Scenario 1: Detecting Malware Beaconing

You notice regular connections to an unknown domain every 5 minutes:

```
[ALERT] infected-host-fj83k.malware-c2.com contacted every 300 seconds
```

**Actions:**
1. Note the device IP making the connections
2. Research the domain (VirusTotal, Google)
3. Isolate the device from the network
4. Run antivirus scan
5. Check other devices for similar behavior

### Scenario 2: IoT Device Phone Home

Your smart TV is contacting analytics servers constantly:

```
[INFO] Device 192.168.1.150 contacted analytics.smarttv-vendor.com every 60 seconds
        → Regular tracking service, likely analytics or ads. Low risk.
```

**Actions:**
1. Normal behavior for many IoT devices
2. Consider network segmentation (IoT VLAN)
3. Check privacy settings on device
4. Block at router if desired

### Scenario 3: Failed Connection Attempts

```
[WARNING] Repeated failed connections to 192.168.1.200:445 (25 attempts).
```

**Actions:**
1. Port 445 = SMB (Windows file sharing)
2. Some device is trying to connect to .200 but failing
3. Could be: misconfigured backup, scanning, or worm
4. Check device at .200 - does it exist?
5. Investigate source of connection attempts

### Scenario 4: Excessive Tracking

```
[WARNING] Device made 250 connections to 89 third-party domains while visiting news-site.com.
        → Detected 47 known tracking/ad services.
```

**Actions:**
1. Very tracker-heavy website
2. Privacy concern, not security concern
3. Use ad blocker (uBlock Origin, Privacy Badger)
4. Consider alternative news sources

## Tips for Effective Monitoring

### 1. Start with Short Captures
Don't monitor for hours on your first run. Start with 5-10 minutes to understand normal traffic.

### 2. Use --alerts-only for Ongoing Monitoring
Reduce noise by filtering out informational messages:
```bash
sudo net-watch live --iface wlan0 --alerts-only
```

### 3. Monitor During Specific Activities
- Browse to a suspicious website
- Run a suspicious application
- Test a new IoT device

### 4. Compare Before and After
- Capture traffic before installing software
- Capture after installation
- Compare differences

### 5. Create a Baseline
Monitor your network during normal usage to understand what's typical for your environment.

### 6. Focus on Unknown Domains
Known trackers (Google, Facebook) are usually harmless. Unknown domains with beaconing = investigate.

## Common False Positives

### Cloud Sync Services
```
[ALERT] sync.cloud-service.com contacted every 120 seconds
```
Legitimate cloud services (Dropbox, OneDrive, iCloud) check for updates regularly.

### Update Checkers
```
[ALERT] updates.software-vendor.com contacted every 3600 seconds
```
Software checking for updates hourly is normal.

### Social Media Apps
```
[WARNING] Device made 50 connections while using social-app.com
```
Social media apps load many third-party resources.

### Gaming Consoles
```
[WARNING] Long-lived connection to game-server.com (8 hours)
```
Online gaming maintains persistent connections.

## Privacy Considerations

**What net-watch CAN see:**
- IP addresses
- Domain names (from DNS)
- Connection timing and patterns
- Unencrypted HTTP content

**What net-watch CANNOT see:**
- HTTPS encrypted content (passwords, messages, etc.)
- VPN tunnel contents
- Content of encrypted protocols

**Best Practices:**
- Only monitor networks you own/control
- Inform users if monitoring shared network
- Don't share packet captures (may contain private data)
- Use device filtering to focus on specific hosts

## Troubleshooting

### "No packets captured"
- Wrong interface name
- No traffic on interface
- Permission issues

### "Permission denied"
- Need root: `sudo net-watch live --iface wlan0`

### "Interface not found"
- Check interface name: `ip link` or `ifconfig`
- Try different interface

### Too many INFO messages
- Use `--alerts-only` flag

### High CPU usage
- Normal for high-traffic networks
- Use `--alerts-only` to reduce output
- Filter by `--device` to reduce processing

## Getting Help

View all commands:
```bash
net-watch --help
```

View command-specific help:
```bash
net-watch live --help
net-watch pcap --help
```
