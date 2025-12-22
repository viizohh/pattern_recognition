# Website Tracking Feature

## New Feature: See Which Websites Traffic Comes From!

net-watch now tracks **which websites you're visiting** and shows you context for network activity.

## How It Works:

When you visit LinkedIn or YouTube, net-watch:
1. **Tracks the primary website** (linkedin.com, youtube.com)
2. **Identifies third-party resources** loaded by that site
3. **Shows context** in alerts and summaries

## What You'll See:

### 1. **At the End of Capture - Website Summary**

When you stop (Ctrl+C), you'll now see:

```
============================================================
Websites Visited:
============================================================

Device: 10.101.7.164
  Websites visited:
    1. linkedin.com
    2. youtube.com
    3. reddit.com
    4. github.com
  Currently on: github.com
    Loaded 12 third-party domains

============================================================
```

This shows you **exactly which websites** were visited and what's currently being browsed.

### 2. **In Verbose Mode - Live Context**

With `--verbose`, you'll see real-time context:

```bash
sudo net-watch live --iface en0 --verbose
```

Output:
```
DNS: linkedin.com (new visit)
DNS: platform.linkedin.com (while visiting linkedin.com)
DNS: static.licdn.com (while visiting linkedin.com)
HTTP: linkedin.com (new visit)
HTTP: ads.linkedin.com (while visiting linkedin.com)
```

Now you can **see exactly which domain is loaded from which website!**

### 3. **Better Tracking Alerts**

Alerts will show more context:

```
[INFO] Device made 45 connections to 12 third-party domains while visiting linkedin.com
        → Common tracking behavior, low risk.
```

Instead of just saying "connections to domains", it tells you **"while visiting linkedin.com"**.

## Usage Examples:

### Basic - Show Websites at End
```bash
sudo net-watch live --iface en0

# Visit some websites (LinkedIn, YouTube, etc.)
# Press Ctrl+C

# You'll see:
# - Alerts during capture
# - List of websites visited at the end
```

### Verbose - See Live Context
```bash
sudo net-watch live --iface en0 --verbose

# You'll see:
#   DNS: youtube.com (new visit)
#   DNS: googlevideo.com (while visiting youtube.com)
#   DNS: ytimg.com (while visiting youtube.com)
```

### Quiet - Just Alerts + Summary
```bash
sudo net-watch live --iface en0 --alerts-only

# You'll see:
# - Only warnings/alerts (no INFO)
# - Website summary at the end
```

## What It Tracks:

### Primary Domains (Sites You Actually Visit):
- linkedin.com
- youtube.com
- reddit.com
- github.com
- news sites, blogs, etc.

### Third-Party Domains (Loaded BY Those Sites):
- google-analytics.com (tracking)
- doubleclick.net (ads)
- facebook.net (social widgets)
- cdn.example.com (content delivery)
- static.site.com (resources)

## How It Determines Primary vs Third-Party:

1. **First domain contacted** = Primary
2. **Known tracking domains** (analytics, ads) = Third-party
3. **CDN domains** (cloudfront, fastly) = Third-party
4. **Domains with real TLDs** (.com, .org) loaded first = Primary

## Example Output:

```
$ sudo net-watch live --iface en0
net-watch v0.1.0 - Live Network Monitor
============================================================

Starting live capture on en0...
Press Ctrl+C to stop

[INFO] 2025-12-19 20:15:30
Device made 23 connections to 8 third-party domains while visiting linkedin.com.
        → Common tracking behavior, low risk.

[WARNING] 2025-12-19 20:16:45
Device made 67 connections to 31 third-party domains while visiting youtube.com.
        → Detected 12 known tracking/ad services.

^C
============================================================
Websites Visited:
============================================================

Device: 10.101.7.164
  Websites visited:
    1. linkedin.com
    2. youtube.com
    3. www.reddit.com
  Currently on: reddit.com
    Loaded 15 third-party domains

============================================================
Capture Summary:
  Packets processed: 4523
  Duration: 125.3 seconds
  Rate: 36.1 packets/sec

Alerts:
  INFO: 12
  WARNING: 3
  ALERT: 0
============================================================
```

## Benefits:

✅ **Know exactly which website** caused an alert
✅ **See all websites visited** by each device
✅ **Understand third-party tracking** per site
✅ **Better context** for security decisions

## Try It Now!

```bash
# Install the updated version
cd /Users/h/ClaudeAssignments/Packets
pip install -e .

# Run with website tracking
sudo net-watch live --iface en0

# Visit LinkedIn and YouTube
# Press Ctrl+C and see the website list!
```

You'll now see **exactly which websites** the traffic is coming from!
