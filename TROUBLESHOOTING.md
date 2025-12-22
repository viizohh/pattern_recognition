# Troubleshooting: No Traffic Showing

## If you're not seeing ANY traffic, try these steps:

### Step 1: Test Without Filters First

```bash
# DON'T filter by device yet - just see if ANY traffic shows
sudo net-watch live --iface en0 --show-all
```

**What you should see immediately:**
- Lots of mDNS announcements
- ARP broadcasts
- TCP/UDP connections
- **If you see NOTHING**, go to Step 2

### Step 2: Verify Your IP Address

```bash
# Get YOUR actual IP (not the broadcast address)
ifconfig en0 | grep "inet "
```

You'll see something like:
```
inet 10.101.7.164 netmask 0xfffffc00 broadcast 10.101.7.255
```

- ✅ **YOUR IP**: `10.101.7.164`
- ❌ **NOT the broadcast**: `10.101.7.255`

### Step 3: Try With YOUR Correct IP

```bash
# Replace with YOUR actual IP from Step 2
sudo net-watch live --iface en0 --device 10.101.7.164 --show-all
```

### Step 4: Generate Traffic

**While net-watch is running**, do these things to generate traffic:

1. **Open a web browser** and visit google.com
2. **Refresh a page**
3. **Check email**
4. **Any internet activity**

**You should see:**
```
[DNS] 10.101.7.164 → google.com
[HTTPS] 10.101.7.164 → google.com:443
[TCP] 10.101.7.164:54321 → 142.250.73.131:443
```

---

## Common Issues:

### Issue: "No packets at all"

**Cause:** Not running with sudo, or wrong interface

**Fix:**
```bash
# Make sure you're using sudo
sudo net-watch live --iface en0 --show-all

# If still nothing, try a different interface
ifconfig  # Look for active interfaces
sudo net-watch live --iface en1 --show-all  # Try en1
```

### Issue: "Seeing other devices but not mine"

**Cause:** Wrong IP address in filter

**Fix:**
```bash
# Double-check your IP
ifconfig en0 | grep "inet " | awk '{print $2}'

# Use the correct IP (example: 10.101.7.164)
sudo net-watch live --iface en0 --device 10.101.7.164 --show-all
```

### Issue: "Only seeing mDNS/ARP, no real traffic"

**Cause:** No actual internet traffic happening

**Fix:**
- **Visit a website** while capture is running
- **Stream a video**
- **Download something**
- You need to actively use the internet!

---

## Quick Diagnostic Commands:

### Test 1: Can you capture at all?
```bash
sudo net-watch live --iface en0 --show-all
# Press Ctrl+C after 5 seconds
# Did you see ANYTHING? If yes, capture works!
```

### Test 2: See YOUR traffic only?
```bash
# Get your IP
MY_IP=$(ifconfig en0 | grep "inet " | awk '{print $2}')
echo "My IP is: $MY_IP"

# Capture YOUR traffic
sudo net-watch live --iface en0 --device $MY_IP --show-all
# Now visit google.com in browser
```

### Test 3: Just see security alerts?
```bash
# Default mode - only shows suspicious stuff
sudo net-watch live --iface en0
# This will be quiet unless there's actual suspicious activity
```

---

## What SHOULD You See?

### On a busy network (with --show-all):
```
[mDNS] 10.101.7.109 → Fawaz's Iphone ._rdlink._tcp.local
[ARP] Who has 10.101.5.162? Tell 10.101.6.121
[DNS] 10.101.7.164 → google.com
[HTTPS] 10.101.7.164 → google.com:443
[TCP] 10.101.6.29:52341 → 142.250.31.95:443
[UDP] 10.101.5.237:54382 → 8.8.8.8:53
... lots more ...
```

### With --device filter (YOUR traffic only):
```
[DNS] 10.101.7.164 → youtube.com
[HTTPS] 10.101.7.164 → youtube.com:443
[DNS] 10.101.7.164 → googlevideo.com
[TCP] 10.101.7.164:54321 → 142.250.73.131:443
```

### Without --show-all (security mode):
```
... quiet ...
[INFO] Device made 23 connections while visiting linkedin.com
... quiet ...
[WARNING] Repeated failed connections detected
```

---

## Still Not Working?

Check these:

1. **Are you using sudo?**
   ```bash
   # Need root for packet capture
   sudo net-watch live --iface en0 --show-all
   ```

2. **Is en0 the right interface?**
   ```bash
   # List all interfaces
   ifconfig
   # Try different ones
   sudo net-watch live --iface en1 --show-all
   ```

3. **Are you generating traffic?**
   - Visit websites while capture is running
   - Don't just let it sit idle

4. **Is your IP correct?**
   ```bash
   ifconfig en0 | grep "inet "
   # Use the IP shown, NOT the broadcast address
   ```

---

## Expected Behavior:

- **--show-all**: VERY noisy, 10+ lines per second
- **--device YOUR_IP --show-all**: Moderate, only YOUR traffic
- **Default (no flags)**: Quiet, only alerts
- **--alerts-only**: Very quiet, only warnings/alerts

If you're in default mode and seeing nothing, **that's normal** - it means no suspicious activity!

Try **--show-all** to see actual traffic.
