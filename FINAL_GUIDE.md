# 🐕 hound - Your Network Monitoring Tool

## Perfect! Here's How It Works:

### **Type `hound` to enter interactive mode:**

```bash
$ hound

.__                             .___
|  |__   ____  __ __  ____    __| _/
|  |  \ /  _ \|  |  \/    \  / __ |
|   Y  (  <_> )  |  /   |  \/ /_/ |
|___|  /\____/|____/|___|  /\____ |
     \/                  \/      \/

hound v0.1.0 - Network Monitoring Tool
Type 'help' or '?' for commands. Type 'quit' or 'exit' to leave.

hound>
```

**🔒 SECURITY FEATURE:** You MUST type `hound` first to enter the interactive shell. You cannot run `hound sniff` directly from bash. This prevents unauthorized network sniffing on your computer!

---

## **Commands:**

### **Application name:** hound 🐕
### **Interactive Shell:** Type `hound` to enter, then use `sniff` commands

---

## All Commands:

### 1. Enter Interactive Shell:
```bash
$ hound
hound>
```

### 2. Show everything (like Wireshark):
```bash
$ hound
hound> sniff live --iface en0 --show-all
```
(Note: Requires sudo, so run: `sudo hound` then enter the command)

### 3. Show only YOUR traffic:
```bash
hound> sniff live --iface en0 --device YOUR_IP --show-all
```

### 4. Security monitoring (quiet):
```bash
hound> sniff live --iface en0 --alerts-only
```

### 5. Analyze a pcap file:
```bash
hound> sniff pcap capture.pcap --show-all
```

### 6. Get help:
```bash
hound> help              # Show available commands
hound> help sniff        # Show sniff usage
```

### 7. Exit the shell:
```bash
hound> quit              # or 'exit'
```

---

## Quick Start:

```bash
# 1. Enter hound interactive shell
$ sudo hound

# 2. You'll see the banner and prompt:
hound>

# 3. Find your interface (from another terminal)
ifconfig

# 4. Start sniffing from within the hound shell!
hound> sniff live --iface en0 --show-all

# 5. Press Ctrl+C to stop capture, then type 'quit' to exit
hound> quit
```

---

## Examples:

### Example 1: See Everything on Network
```bash
$ sudo hound

.__                             .___
|  |__   ____  __ __  ____    __| _/
|  |  \ /  _ \|  |  \/    \  / __ |
|   Y  (  <_> )  |  /   |  \/ /_/ |
|___|  /\____/|____/|___|  /\____ |
     \/                  \/      \/

hound v0.1.0 - Network Monitoring Tool
Type 'help' or '?' for commands. Type 'quit' or 'exit' to leave.

hound> sniff live --iface en0 --show-all

.__                             .___
|  |__   ____  __ __  ____    __| _/
|  |  \ /  _ \|  |  \/    \  / __ |
|   Y  (  <_> )  |  /   |  \/ /_/ |
|___|  /\____/|____/|___|  /\____ |
     \/                  \/      \/

hound v0.1.0 - Live Network Monitor
============================================================

Starting live capture on en0...
Press Ctrl+C to stop

[mDNS] 10.101.7.109 → Device announcements
[DNS] 10.101.7.164 → google.com
[HTTPS] 10.101.7.164 → google.com:443
[TCP] 10.101.6.29:52341 → 142.250.31.95:443
...
```

### Example 2: Monitor YOUR Traffic Only
```bash
$ sudo hound
hound> sniff live --iface en0 --device 10.101.7.164 --show-all

[DNS] 10.101.7.164 → youtube.com
[HTTPS] 10.101.7.164 → youtube.com:443
[DNS] 10.101.7.164 → googlevideo.com
```

### Example 3: Security Monitoring (Quiet)
```bash
$ sudo hound
hound> sniff live --iface en0 --alerts-only

... quiet unless suspicious activity ...

[ALERT] Device contacted suspicious-domain.com every 60 seconds
        → Behavior matches automated beaconing patterns.
```

### Example 4: Analyze a PCAP File
```bash
$ hound
hound> sniff pcap network_capture.pcap --show-all

.__                             .___
|  |__   ____  __ __  ____    __| _/
|  |  \ /  _ \|  |  \/    \  / __ |
|   Y  (  <_> )  |  /   |  \/ /_/ |
|___|  /\____/|____/|___|  /\____ |
     \/                  \/      \/

hound v0.1.0 - PCAP Analyzer
============================================================

Analyzing pcap file: network_capture.pcap...
...
```

---

## Command Structure Breakdown:

```
# From bash:
$ hound                         → Enters interactive shell (shows ASCII art)
$ hound sniff                   → Shows help message (does NOT run sniff)

# From within hound shell:
hound>                          → Shell prompt (ready for commands)
hound> help                     → Shows available commands
hound> sniff                    → Shows sniff usage
hound> sniff live               → Error (needs --iface)
hound> sniff live --iface en0   → Start monitoring (requires sudo hound)
hound> sniff pcap file.pcap     → Analyze pcap file
hound> quit                     → Exit hound shell
```

---

## All Modes:

| Command (within hound shell) | What It Shows |
|-------------------------------|--------------|
| `sniff live --iface en0 --show-all` | **Everything** (like Wireshark) |
| `sniff live --iface en0 --device IP --show-all` | **Your device only** |
| `sniff live --iface en0` | **Security alerts only** |
| `sniff live --iface en0 --alerts-only` | **Warnings/alerts only** |
| `sniff live --iface en0 --verbose` | **Detailed technical info** |

**Note:** For live capture, run `sudo hound` first to enter the shell with root privileges.

---

## Summary:

- ✅ **Application name:** hound 🐕
- ✅ **Type `hound`** to enter interactive shell (shows ASCII art)
- ✅ **Shell commands:** `sniff live` or `sniff pcap` (from within shell)
- ✅ **"sniff" is used** to observe network traffic
- 🔒 **Security feature:** Cannot run `hound sniff` directly from bash - must enter shell first!
- ✅ **Exit commands:** `quit` or `exit` to leave the shell

---

## You're All Set! 🎉

```bash
# Type this to get started:
$ sudo hound

# You'll see:
hound>

# Then you can run sniff commands:
hound> sniff live --iface en0 --show-all

# When done:
hound> quit
```

**Security Note:** The interactive shell prevents unauthorized users from sniffing your network - they must know to type `hound` first!
