# 🔍 Hound OSINT - Passive Domain Intelligence

**Ethical passive reconnaissance for defensive security training and education.**

---

## ⚠️ ETHICAL USE POLICY

### ✅ **PERMITTED USES:**
- Educational security training
- Defensive security (Blue Team) assessments
- Security posture reviews of domains you own/manage
- CTF competitions and security exercises
- Authorized penetration testing with written permission
- Security research on public data only

### ❌ **PROHIBITED USES:**
- Unauthorized reconnaissance of third-party domains
- Credential testing or account enumeration
- Mailbox verification attempts
- Login probing or password reset abuse
- Email spamming or phishing
- Any malicious or illegal activity

**By using this tool, you agree to use it ethically, legally, and responsibly.**

---

## 🎯 What is Passive OSINT?

**Passive OSINT** means gathering information from **publicly available sources** without interacting with the target system in ways that could be detected or leave traces.

### What This Tool Does (✅ PASSIVE):
- ✅ Queries public DNS records (anyone can do this)
- ✅ Searches Certificate Transparency logs (public SSL certificate database)
- ✅ Scrapes publicly accessible webpages
- ✅ Checks domain-level email configuration (MX/SPF/DMARC)
- ✅ Generates keyword-based email guesses (but does NOT verify them)

### What This Tool Does NOT Do (❌ ACTIVE):
- ❌ NO SMTP VRFY/EXPN commands
- ❌ NO password reset probing
- ❌ NO login attempts
- ❌ NO mailbox existence verification
- ❌ NO "is this email registered" checks
- ❌ NO credential stuffing

---

## 🚀 Quick Start

### Installation:

```bash
# 1. Navigate to hound directory
cd /path/to/Packets

# 2. Install dependencies
pip install -r requirements.txt

# 3. Install hound in editable mode
pip install -e .

# 4. Launch hound
hound
```

### Basic Usage:

```bash
# Enter hound interactive shell
$ hound

# Investigate a domain (table output)
hound> dig example.com

# Get JSON output
hound> dig example.com --format json

# Save results to file
hound> dig example.com --output results.json

# Use polite mode (slower, more respectful)
hound> dig example.com --polite

# Custom keywords for email guessing
hound> dig example.com --keywords "security,press,admin"

# Load keywords from file
hound> dig example.com --keywords-file keywords.txt

# Limit pages scraped
hound> dig example.com --max-pages 5
```

---

## 📋 Features

### 1. **RDAP/WHOIS Intelligence**
- Domain registration date
- Registrar information
- Nameservers
- Contact information (if publicly available)
- Domain status

### 2. **DNS Enumeration**
- A/AAAA records (IP addresses)
- NS records (nameservers)
- MX records (mail servers)
- TXT records (SPF, DMARC, DKIM hints)
- SOA record (zone authority)

### 3. **Certificate Transparency Discovery**
- Passive subdomain enumeration via CT logs
- Discovers:
  - mail.example.com
  - vpn.example.com
  - dev.example.com
  - staging.example.com
- Uses crt.sh (free, no API key needed)

### 4. **Web Contact Extraction**
- Scrapes public contact pages:
  - `/`, `/contact`, `/about`, `/team`, `/staff`
  - `/legal`, `/privacy`, `/terms`, `/support`
- Extracts:
  - Email addresses
  - Phone numbers
  - Names
  - Organizations

### 5. **Email Readiness Checks (Safe)**
- For discovered email domains:
  - ✅ MX records exist (can receive email)
  - ✅ SPF record present (email security)
  - ✅ DMARC record present (email policy)
- ❌ Does NOT check individual mailbox existence

### 6. **Keyword-Based Email Guessing**
- Generates probable addresses: `security@domain`, `admin@domain`
- Marks as "GUESSED" (unverified)
- Only assesses domain-level readiness (MX/SPF/DMARC)

---

## 📊 Output Formats

### Table Format (Default):
Beautiful Rich tables in terminal with color-coded sections.

### JSON Format:
Structured JSON for programmatic use:

```json
{
  "domain": "example.com",
  "timestamp": "2024-12-20T10:30:00Z",
  "rdap": { ... },
  "dns": { ... },
  "ct_subdomains": [...],
  "web_findings": { ... },
  "guessed_emails": { ... },
  "email_validation": { ... },
  "risk_notes": [...],
  "errors": [...]
}
```

---

## 🛡️ Blue Team / Defensive Use

### How Security Teams Can Use This Tool:

1. **Email Security Audit:**
   - Check if SPF/DMARC records are properly configured
   - Identify missing email authentication records
   - Action: Add SPF and DMARC to prevent spoofing

2. **Subdomain Discovery:**
   - Find subdomains exposed in CT logs
   - Identify dev/staging/test environments that shouldn't be public
   - Action: Review subdomain exposure, add authentication

3. **Information Leakage:**
   - See what contact info is publicly available
   - Check if sensitive emails are exposed
   - Action: Limit public exposure of internal contacts

4. **Attack Surface Mapping:**
   - Understand what attackers can discover passively
   - Identify potential phishing targets
   - Action: Security awareness training for exposed contacts

5. **DNS Configuration Review:**
   - Verify nameservers are correct
   - Check for stale DNS records
   - Action: Clean up DNS, remove unused records

---

## 🔧 Advanced Options

### Rate Limiting & Politeness:

```bash
# Default: 1 second delay between requests
hound> dig example.com

# Polite mode: 3+ second delays
hound> dig example.com --polite

# Custom delay
hound> dig example.com --delay 5

# Faster (use responsibly!)
hound> dig example.com --delay 0.5
```

### Request Timeouts:

```bash
# Default: 10 second timeout
hound> dig example.com

# Longer timeout for slow servers
hound> dig example.com --timeout 30
```

### Keywords File Format:

Create `keywords.txt`:
```
# Security contacts
security
abuse
csirt

# Press contacts
press
media
pr

# Admin contacts
admin
webmaster
postmaster
```

Use it:
```bash
hound> dig example.com --keywords-file keywords.txt
```

---

## 🧪 Example Output

```
hound> dig example.com

╔═══════════════════════════════════════════════════════════════╗
║  🔍 HOUND OSINT - Passive Domain Intelligence                ║
║                                                               ║
║  ⚠️  ETHICAL USE ONLY - Educational/Defensive Purposes       ║
║                                                               ║
║  This tool performs PASSIVE reconnaissance only:             ║
║  ✓ Public DNS records, CT logs, webpages                     ║
║  ✓ Domain-level email validation (MX/SPF/DMARC)              ║
║  ✗ NO mailbox verification or account enumeration            ║
║  ✗ NO credential testing or login attempts                   ║
║                                                               ║
║  Use responsibly. Respect rate limits. Obey laws.            ║
╚═══════════════════════════════════════════════════════════════╝

🔍 Investigating: example.com

📋 Collecting RDAP/WHOIS data...
🌐 Querying DNS records...
🔐 Searching Certificate Transparency logs...
🌐 Scraping public contact pages (max 10)...
🔮 Generating keyword-based email guesses...
✉️  Validating email domain configuration...

┌────────────────────── Domain Registration (RDAP) ──────────────────────┐
│ Field      │ Value                                                    │
├────────────┼──────────────────────────────────────────────────────────┤
│ Registrar  │ Example Registrar Inc.                                  │
│ Created    │ 1995-08-14                                              │
│ Updated    │ 2024-01-15                                              │
│ Expires    │ 2025-08-13                                              │
│ Status     │ clientDeleteProhibited, clientTransferProhibited        │
└────────────┴──────────────────────────────────────────────────────────┘

[... more tables showing DNS, CT subdomains, web findings, etc ...]

⚠️  Security Observations:
  • No SPF record found - domain is vulnerable to email spoofing.
    Blue team: Add SPF record to prevent email forgery.
  • Development/staging subdomains found (3).
    Blue team: Ensure these are properly secured and not exposing sensitive data.
```

---

## 🧑‍💻 For Developers

### Running Tests:

```bash
# Run unit tests
python -m unittest tests.osint.test_parsers -v

# All tests should pass (16 tests)
```

### Project Structure:

```
net_watch/osint/
├── __init__.py               # Main module
├── cli.py                    # OSINT orchestrator
├── utils.py                  # Utilities (rate limiting, normalization)
├── collectors/
│   ├── rdap.py              # RDAP/WHOIS collector
│   ├── dns.py               # DNS enumeration
│   ├── ct.py                # Certificate Transparency
│   └── web.py               # Web scraping
├── parsers/
│   ├── emails.py            # Email extraction
│   ├── phones.py            # Phone extraction
│   └── entities.py          # Name/org extraction
└── output/
    ├── json_output.py       # JSON formatter
    └── table.py             # Rich table formatter
```

---

## 📚 Dependencies

- **requests** - HTTP client for web scraping
- **dnspython** - DNS queries
- **beautifulsoup4** - HTML parsing
- **tldextract** - Domain parsing and validation
- **rich** - Beautiful terminal tables

---

## 🤝 Contributing

This is an educational tool for defensive security training. Contributions that enhance passive reconnaissance capabilities or improve blue team utility are welcome.

**Pull requests must:**
- Maintain passive-only reconnaissance
- Not add active verification techniques
- Include tests
- Follow ethical guidelines

---

## 📄 License

Part of the Hound network monitoring tool.
For educational and defensive security purposes only.

---

## 📞 Support

For issues or questions:
- Check the help: `hound> help dig`
- Review the ethics banner
- Remember: Passive reconnaissance only!

---

## 🙏 Acknowledgments

- **crt.sh** - Free Certificate Transparency log search
- **ARIN** - RDAP bootstrap service
- **Scapy** - Packet manipulation library

---

**Remember: With great reconnaissance comes great responsibility. Use ethically! 🐕**
