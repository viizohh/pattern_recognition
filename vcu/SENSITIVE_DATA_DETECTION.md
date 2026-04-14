# Sensitive Data Detection Feature

## Overview

VCU now automatically detects and alerts on sensitive information being transmitted in cleartext over the network. This helps identify security risks where passwords, credit cards, API keys, and other sensitive data are exposed.

## What It Detects

### Critical (CRITICAL Alert Level)
- **Passwords** - From login forms, authentication requests
- **Credit Card Numbers** - Validated with Luhn algorithm
- **Social Security Numbers** - Format: XXX-XX-XXXX
- **API Keys** - Common API key patterns

### High Risk (ALERT Level)
- **Email Addresses** - Any email format
- **Usernames** - From login forms
- **Bearer Tokens** - OAuth/JWT bearer tokens
- **JWT Tokens** - JSON Web Tokens

## How It Works

### Packet Analysis
1. Captures packets with payload data
2. Extracts text content from Raw layer
3. Runs regex patterns to find sensitive data
4. Validates findings (e.g., Luhn check for credit cards)
5. Creates alerts for each finding

### Security Features
- **Automatic masking**: Credit cards shown as `****-****-****-1234`
- **SSN masking**: Shown as `***-**-1234`
- **API key masking**: Shown as `sk12...AB34`
- **Deduplication**: Same value only alerted once
- **Context**: Shows surrounding text for each finding

## Example Output

When sensitive data is detected:

```
[CRITICAL] 2026-04-14 18:30:45
Sensitive data detected: Password sent from 192.168.1.100 to 93.184.216.34
        → Password transmitted in cleartext over TCP:80.
          This is a serious security risk as the data can be intercepted.

Technical Details:
  Value: myp@ssw0rd
  Context: username=john&password=myp@ssw0rd&submit=Login

[CRITICAL] 2026-04-14 18:31:22
Sensitive data detected: Credit Card Number sent from 192.168.1.100 to 10.0.0.50
        → Credit Card Number transmitted in cleartext over TCP:443.
          This is a serious security risk as the data can be intercepted.

Technical Details:
  Value: ****-****-****-5678
  Context: card_number=4532-1234-5678-9010&cvv=123
```

### Summary Report

At the end of each capture session:

```
============================================================
SENSITIVE DATA DETECTED:
============================================================
  Password: 3 instance(s)
  Email: 12 instance(s)
  Credit Card: 1 instance(s)
  Api Key: 2 instance(s)

WARNING: Sensitive data was transmitted in cleartext!
Check alerts above for details.
============================================================
```

## What Gets Detected

### Passwords
Looks for common parameter names:
- `password=value`
- `passwd=value`
- `pwd=value`
- `pass=value`

### Email Addresses
Standard email format: `user@domain.com`

### Credit Cards
- Detects formats: `4532-1234-5678-9010` or `4532123456789010`
- Validates using Luhn algorithm (checksum)
- Filters out false positives

### API Keys
Looks for patterns like:
- `api_key=sk-ant-...`
- `apikey: Bearer xyz...`
- `access_token=...`

### Usernames
Common parameter names:
- `username=value`
- `user=value`
- `email=value` (in auth context)
- `login=value`

## Protocols Monitored

Payload parsing works on:
- **HTTP (port 80)** - Cleartext web traffic
- **FTP (port 21)** - File transfers
- **Telnet (port 23)** - Remote access
- **SMTP (port 25)** - Email
- **Any TCP/UDP** with text payload

**Note**: HTTPS (port 443) is encrypted, so sensitive data in HTTPS is safe and won't be detected.

## Use Cases

### 1. Security Audit
Identify applications transmitting sensitive data insecurely:
```bash
vcu> sniff live --iface en0
# Browse/use applications
# Check for sensitive data alerts
```

### 2. Developer Testing
Ensure your application doesn't leak sensitive data:
```bash
vcu> sniff live --iface en0 --device 192.168.1.100
# Test your app's login/checkout flows
# Verify no cleartext passwords or credit cards
```

### 3. Network Compliance
Check network for PCI-DSS, HIPAA, GDPR violations:
```bash
vcu> sniff pcap network_capture.pcap
# Review sensitive data findings
# Generate compliance report
```

## Security Considerations

### Data Privacy
- Sensitive values are automatically masked in reports
- Only partial values shown (last 4 digits for cards)
- Full values stored temporarily in memory during scan
- Data cleared when scan completes

### False Positives
Some patterns may match non-sensitive data:
- Test credit cards (4111-1111-1111-1111)
- Example emails in documentation
- Dummy API keys in code samples

The detector filters common false positives but review findings carefully.

### HTTPS Traffic
- **HTTPS is encrypted** - sensitive data in HTTPS won't be detected
- This is GOOD - it means the data is protected
- Alerts only trigger for cleartext protocols (HTTP, FTP, Telnet)

## Cost Optimization

The AI analysis now uses **Claude Haiku** instead of Sonnet:
- **~10x cheaper** than Sonnet
- **Faster** response times (5-15 seconds vs 15-30 seconds)
- **Still accurate** for security analysis
- Your $5 credit goes much further

Cost comparison:
- **Sonnet**: ~$0.05-0.10 per analysis
- **Haiku**: ~$0.005-0.01 per analysis
- **Haiku = 500+ analyses with $5 credit!**

## Advanced Features

### Pattern Customization
To detect custom sensitive data patterns, edit:
```python
# net_watch/parsers/payload.py
self.patterns = {
    'your_custom_type': re.compile(r'your-regex-here'),
    ...
}
```

### Integration with AI Analysis
Sensitive data findings are included in AI analysis reports:
```bash
vcu> sniff live --iface en0 --ai
```

The AI will:
- Assess risk of data exposure
- Identify compliance violations
- Recommend encryption solutions
- Correlate with other threats

## Limitations

1. **Encrypted traffic**: Cannot inspect HTTPS/TLS content (by design)
2. **Binary protocols**: Only parses text-based protocols
3. **Compression**: Cannot parse compressed payloads
4. **False positives**: May flag test/dummy data
5. **Performance**: Slight overhead from regex matching

## Best Practices

### For Organizations
1. Run periodic network scans for sensitive data exposure
2. Alert security team on CRITICAL findings
3. Implement network encryption (HTTPS, VPN)
4. Train developers on secure coding
5. Use findings for compliance audits

### For Developers
1. Test applications before deployment
2. Always use HTTPS for sensitive data
3. Never log passwords or credit cards
4. Use secure authentication (OAuth, JWT over HTTPS)
5. Implement TLS for all protocols

### For Security Teams
1. Monitor for credential leakage
2. Identify legacy systems using cleartext
3. Track PCI-DSS compliance
4. Investigate suspicious data flows
5. Generate incident reports from findings

## Example Workflow

```bash
# 1. Start VCU with AI analysis
vcu
vcu> sniff live --iface en0 --ai

# 2. Let it run while network is active
# (captures traffic for 5-10 minutes)

# 3. Stop with Ctrl+C

# 4. Review findings:
#    - Immediate alerts show sensitive data in real-time
#    - Summary shows counts by type
#    - AI report includes data exposure analysis

# 5. Take action:
#    - Fix applications sending cleartext passwords
#    - Enable HTTPS where needed
#    - Update security policies
#    - Generate compliance report
```

## Compliance Mapping

### PCI-DSS
- **Requirement 4.1**: Detects unencrypted card data transmission
- **Requirement 3.4**: Identifies card numbers in transit

### HIPAA
- Detects PHI (SSN, patient data) in cleartext
- Alerts on unencrypted medical information

### GDPR
- Identifies PII exposure (emails, names, etc.)
- Tracks data transmission to assess compliance

## Troubleshooting

### "No sensitive data detected" but I know there should be
- Check if traffic is using HTTPS (encrypted - this is good!)
- Verify packets have payload data (`--show-all` to see packets)
- Try different regex patterns for custom formats

### Too many false positives
- Review `payload.py` patterns
- Add filters for known test values
- Adjust validation logic (e.g., stricter email validation)

### Performance impact
- Payload parsing adds ~5-10% CPU overhead
- Minimal impact on small networks
- For high-traffic networks, use `--device` to filter

---

**Remember**: Detecting sensitive data in cleartext is a **security feature**. It helps you identify and fix dangerous practices before attackers exploit them!
