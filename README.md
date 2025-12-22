# Hound - Network Security & OSINT Intelligence Platform

A comprehensive command-line security toolkit designed for defensive security operations, threat intelligence, and educational cybersecurity training.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

### 1. Network Traffic Analysis (Sniff)
- Real-time packet capture and analysis
- Protocol parsing (DNS, HTTP, HTTPS, TCP)
- Threat detection:
  - Beaconing detection for C2 communications
  - Tracking pixel identification
  - Network anomaly detection
- Session tracking and connection analysis
- PCAP file analysis support

### 2. Passive OSINT Intelligence (Dig)
- Automated domain reconnaissance using public data
- DNS record enumeration (A, AAAA, MX, NS, TXT, SPF, DMARC)
- RDAP/WHOIS registration data
- Certificate Transparency log analysis
- Web scraping for public contact information
- Email security validation
- Export to JSON/formatted tables

### 3. Breach Intelligence (Fetch)
- Privacy-preserving password breach checking via HIBP API
  - Uses k-anonymity (only first 5 chars of hash sent)
  - Checks against 800+ million compromised passwords
  - NO API KEY REQUIRED
- Domain-level breach checking (14 major breaches)
- Breach severity classification
- Security recommendations

## Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/hound.git
cd hound

# Install dependencies
pip install -r requirements.txt

# Run hound
python -m net_watch.cli
# or
hound
```

## Quick Start

```bash
# Start the interactive shell
hound

# Check for breaches
fetch --email test@example.com
fetch --password MyPassword123

# Investigate a domain
dig example.com

# Monitor network traffic (requires sudo)
sudo hound
sniff live --iface en0 --show-all

# Exit
quit
```

## Usage

### Network Traffic Analysis

```bash
# Live capture
sniff live --iface en0 --show-all

# Monitor specific device
sniff live --iface en0 --device 192.168.1.100

# Alert-only mode (threat detection)
sniff live --iface en0 --alerts-only

# Analyze PCAP file
sniff pcap capture.pcap --show-all
```

### OSINT Investigation

```bash
# Basic domain investigation
dig example.com

# With keywords for email guessing
dig example.com --keywords "admin,security,support"

# Save results
dig example.com --output report.json

# JSON output
dig example.com --format json
```

### Breach Checking

```bash
# Check email domain
fetch --email test@yahoo.com

# Check password (HIBP k-anonymity)
fetch --password MyPassword123

# Check domain
fetch --domain linkedin.com

# JSON output
fetch --email test@example.com --format json

# Save report
fetch --email test@example.com --output breach_report.json
```

## Requirements

- Python 3.8+
- Root/sudo privileges (for packet capture)
- Network interface access

See `requirements.txt` for Python dependencies.

## Architecture

```
net_watch/
├── breach/          # Breach intelligence module
├── osint/           # OSINT collection and analysis
├── detectors/       # Threat detection algorithms
├── parsers/         # Protocol parsers
├── tracking/        # Connection and session tracking
└── shell.py         # Interactive CLI
```

## Ethical Use

**WARNING: ETHICAL USE ONLY**

This tool is designed for:
- Defensive security operations
- Educational purposes
- Authorized security assessments
- Personal account security checks

**Prohibited uses:**
- Unauthorized network monitoring
- Privacy violations
- Credential stuffing attacks
- Any malicious activities

Always comply with applicable laws (GDPR, CCPA, etc.) and obtain proper authorization.

## Privacy & Security

- **No data storage**: Tool does not log queries or results by default
- **Privacy-preserving**: Password checking uses k-anonymity
- **Local analysis**: Most operations performed locally
- **Minimal external calls**: Only HIBP API for password checks

## Limitations

### Email Checking
- Checks **DOMAIN-level** breaches only (e.g., @yahoo.com)
- Cannot verify if specific email address was compromised
- For accurate email checking, use [haveibeenpwned.com](https://haveibeenpwned.com)

### Breach Database
- Contains 14 major public breaches
- Not comprehensive of all breaches
- Educational purposes only

### Network Capture
- Requires root/sudo privileges
- Interface-specific (en0, eth0, etc.)
- May not capture encrypted traffic content

## Contributing

Contributions welcome! This is an educational security tool focused on defensive operations.

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is for educational and defensive security purposes only. Users are responsible for ensuring compliance with all applicable laws and regulations. The authors assume no liability for misuse.

## Author

Built with Python, Scapy, Rich, and open-source security tools.

## Acknowledgments

- [Have I Been Pwned](https://haveibeenpwned.com/) - Troy Hunt's excellent breach checking service
- Public breach disclosure reports
- Open-source security community
