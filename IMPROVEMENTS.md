# Improvements to Reduce False Positives

## What Was Fixed:

### 1. **Local Network Services (.local domains)**
**Problem**: Alerting on Apple Bonjour/mDNS services like:
- `_printer._tcp.local` (printer discovery)
- `_airplay._tcp.local` (AirPlay devices)
- `_companion-link._tcp.local` (device handoff)

**Fix**: Added filter to ignore all `.local` domains - these are normal local network discovery.

### 2. **Ephemeral Ports (49152-65535)**
**Problem**: Alerting on ports like 65040, 65019, etc.

**Fix**: These are normal client-side temporary ports used for outbound connections. Now filtered out.

### 3. **CDN Connection Failures**
**Problem**: Alerting on Fastly CDN (151.101.x.x) connection retries

**Fix**: CDNs often retry failed connections - this is normal. Now requires 20+ failures before alerting.

### 4. **High Entropy for Legitimate Services**
**Problem**: Device names and service announcements have high randomness

**Fix**: Now ignores high entropy for:
- Local network services (`.local`)
- Known CDN domains (`.cloudfront.net`, `.fastly.net`)
- Still alerts if entropy is VERY high (>5.0)

## Try Again:

```bash
sudo net-watch live --iface en0 --alerts-only
```

You should see **far fewer false positives** now. Alerts will focus on:
- ✅ Actually suspicious beaconing patterns
- ✅ Unusual port activity (not ephemeral)
- ✅ Real DGA domains (not local services)
- ✅ Excessive tracking
- ✅ Genuine connection anomalies

## What You'll Still See (and should):

- **Beaconing to unknown domains** - legitimate alerts
- **Excessive third-party tracking** - privacy concern
- **Port scanning** - security concern
- **Unusual connection patterns** - worth investigating

## What You Won't See Anymore (false positives):

- ❌ Apple AirPlay/Bonjour services
- ❌ Printer discovery
- ❌ High client ports (65000+)
- ❌ Normal CDN retries
- ❌ Device names with high entropy
