# Breach Fetch Module

Data breach intelligence for defensive security and educational purposes.

## ⚠️ ETHICAL USE ONLY

This module is designed for **defensive security** purposes:

### ✅ Permitted Uses
- Check your own email addresses, passwords, and accounts
- Security audits with explicit permission
- Educational and training purposes
- Blue team defensive operations
- Password hygiene assessments

### ❌ Prohibited Uses
- Checking others' data without permission
- Using breach data for unauthorized access
- Credential stuffing attacks
- Account takeover attempts
- Any malicious or unauthorized activities

**DISCLAIMER**: Results are intelligence indicators, not definitive proof. Always comply with applicable laws (GDPR, CCPA, etc.).

---

## Features

### 1. Password Breach Checking
- Uses **HIBP (Have I Been Pwned) Pwned Passwords API**
- **NO API KEY REQUIRED** - completely free service
- **Privacy-preserving k-anonymity** - your password never leaves your machine
- SHA-1 hashing with only first 5 characters sent to API
- Severity scoring based on breach frequency

### 2. Email & Domain Breach Checking
- Local database of 15 major known breaches
- Email address breach history
- Domain-wide breach analysis
- Confidence scoring for match quality

### 3. Username & Phone Checking
- Returns breaches that exposed username/phone data
- Useful for understanding exposure surface
- Includes appropriate disclaimers

### 4. Flexible Output Formats
- **Table format** (default) - Beautiful Rich tables with colors
- **JSON format** - Machine-readable structured data
- **Report saving** - Export results to timestamped JSON files

---

## Usage

### Basic Commands

Access the fetch command through the hound shell:

```bash
# Start hound shell
hound

# Check email for breaches
fetch --email test@example.com

# Check password (uses HIBP k-anonymity)
fetch --password MyPassword123

# Check domain
fetch --domain example.com

# Check username exposures
fetch --username johndoe

# Check phone number exposures
fetch --phone +1-555-123-4567
```

### Output Options

```bash
# JSON output instead of table
fetch --email test@example.com --format json

# Save report to file
fetch --email test@example.com --output report.json

# Suppress ethics banner
fetch --email test@example.com --no-banner
```

### Short Form Arguments

```bash
# Short forms available
fetch -e test@example.com      # email
fetch -p MyPassword123          # password
fetch -d example.com            # domain
fetch -u johndoe                # username
fetch -ph +1-555-1234           # phone
```

### Get Help

```bash
# Show detailed help
fetch --help

# Show command list in shell
help fetch
```

---

## How It Works

### Password Checking (HIBP k-Anonymity)

The password checker uses a privacy-preserving technique called **k-anonymity**:

1. **Hash your password** with SHA-1 locally on your machine
2. **Send only the first 5 characters** of the hash to the HIBP API
3. **Receive a list** of all password hashes starting with those 5 chars
4. **Check locally** if your full hash appears in the list

**Example:**
- Password: `P@ssw0rd`
- SHA-1 hash: `21BD12DC183F740EE76F27B78EB39C8AD972A757`
- Sent to API: `21BD1` (first 5 characters only)
- API returns: All hashes starting with `21BD1`
- Your machine checks if full hash matches locally

**Privacy guarantee:** Your actual password is never transmitted over the network.

### Email/Domain Checking (Local Database)

The email and domain checker uses a local database containing metadata about major public breaches:

- **15 major breaches** included (Adobe, LinkedIn, Yahoo, Facebook, etc.)
- **No actual leaked data** - only breach metadata
- **Public information** from breach disclosure reports
- **Domain matching** against known affected domains
- **Wildcard matching** for collection-style breaches (e.g., Collection #1)

**Confidence Scoring:**
- Specific domain match: 90% confidence
- Wildcard match: 50% confidence
- Average calculated across all matches

---

## Data Sources

### Passwords
- **Source:** [Have I Been Pwned (HIBP) Pwned Passwords API](https://haveibeenpwned.com/Passwords)
- **API Key Required:** NO (completely free)
- **Coverage:** 800+ million passwords from real-world breaches
- **Privacy:** k-anonymity ensures password safety

### Email/Domain/Username/Phone
- **Source:** Local breach metadata database
- **Coverage:** 15 major public breaches
- **Data Stored:** Metadata only (name, date, count, exposed fields)
- **No Actual Leaked Data:** Database contains NO actual user credentials

### Major Breaches Included

| Breach | Year | Records | Severity |
|--------|------|---------|----------|
| Yahoo | 2013 | 3 billion | Critical |
| Collection #1 | 2019 | 773 million | Critical |
| Facebook | 2019 | 533 million | High |
| Marriott/Starwood | 2018 | 500 million | Critical |
| MySpace | 2013 | 360 million | High |
| LinkedIn | 2012 | 165 million | High |
| Adobe | 2013 | 153 million | High |
| Equifax | 2017 | 147 million | Critical |
| Target | 2013 | 110 million | High |
| Capital One | 2019 | 106 million | Critical |
| Anthem | 2015 | 80 million | Critical |
| PlayStation Network | 2011 | 77 million | High |
| Dropbox | 2012 | 68 million | High |
| Uber | 2016 | 57 million | High |
| Twitter | 2022 | 5.4 million | Medium |

---

## Output Examples

### Password Check - Safe

```
✅ PASSWORD SAFE
╭─────────────┬──────────────────────╮
│ Result      │ Details              │
├─────────────┼──────────────────────┤
│ Status      │ NOT FOUND IN BREACHES│
│ Hash Prefix │ A94B3                │
╰─────────────┴──────────────────────╯

✅ This password was not found in known breach databases.
Note: This doesn't guarantee the password is strong - always use unique, complex passwords.
```

### Password Check - Compromised

```
🚨 PASSWORD COMPROMISED
╭─────────────┬───────────────────╮
│ Result      │ Details           │
├─────────────┼───────────────────┤
│ Status      │ FOUND IN BREACHES │
│ Occurrences │ 2,254,650         │
│ Severity    │ CRITICAL          │
│ Hash Prefix │ CBFDA             │
╰─────────────┴───────────────────╯

💡 Recommendation:
   🚨 CRITICAL: This password has been seen 2,254,650 times in breaches! Change immediately!
```

### Email Check

```
⚠️  2 breach(es) found for: test@yahoo.com
Confidence: 70%

                          📊 Breach Details (2 found)
╭───────────────┬────────────┬───────────────┬──────────────────────┬──────────╮
│ Breach        │ Date       │       Records │ Data Exposed         │ Severity │
├───────────────┼────────────┼───────────────┼──────────────────────┼──────────┤
│ Yahoo         │ 2013-08-01 │ 3,000,000,000 │ Email, Password      │ CRITICAL │
│               │            │               │ (hashed), Name...    │          │
│ Collection #1 │ 2019-01-16 │   773,000,000 │ Email, Password      │ CRITICAL │
│               │            │               │ (plaintext)          │          │
╰───────────────┴────────────┴───────────────┴──────────────────────┴──────────╯

💡 Recommendations:
🚨 2 CRITICAL breach(es) found!
📊 Total 2 breach(es) found
🔐 Recommended actions:
   • Change passwords immediately
   • Enable 2FA/MFA if not already enabled
   • Monitor accounts for suspicious activity
   • Check credit reports if financial data was exposed
```

### JSON Output

```json
{
  "query": {
    "type": "email",
    "value": "test@adobe.com",
    "timestamp": "2025-12-20T09:07:22.379296Z"
  },
  "result": {
    "email": "test@adobe.com",
    "breaches": [
      {
        "name": "Adobe",
        "date": "2013-10-04",
        "records": 153000000,
        "data_exposed": ["Email", "Password (hashed)", "Username"],
        "domains": ["adobe.com"],
        "description": "Adobe user database breach exposing 153 million records",
        "severity": "high",
        "source": "Public disclosure"
      }
    ],
    "total_breaches": 1,
    "confidence": 90.0,
    "recommendation": "..."
  }
}
```

---

## Blue Team Use Cases

### 1. Password Hygiene Assessment
**Scenario:** Security team wants to check if employee passwords are compromised

```bash
# Check passwords from security audit
fetch --password EmployeePassword123
```

**Action if compromised:** Require immediate password change and enable MFA.

### 2. Breach Response Planning
**Scenario:** Organization uses yahoo.com for employee emails, check exposure

```bash
# Check domain for breaches
fetch --domain yahoo.com
```

**Action:** Review which data types were exposed, implement additional monitoring.

### 3. Incident Investigation
**Scenario:** Suspicious account activity, check if credentials leaked

```bash
# Check specific email
fetch --email employee@company.com

# Save detailed report
fetch --email employee@company.com --output incident_12345.json
```

**Action:** If breached, force password reset, review account logs for unauthorized access.

### 4. Security Awareness Training
**Scenario:** Demonstrate to employees why password reuse is dangerous

```bash
# Check common passwords
fetch --password password123
fetch --password qwerty
fetch --password 123456
```

**Result:** Show employees how many times these passwords appear in breaches.

### 5. Vendor Risk Assessment
**Scenario:** Evaluating third-party vendor security posture

```bash
# Check vendor domain
fetch --domain vendorcompany.com
```

**Action:** If major breaches found, require vendor to demonstrate improved security controls.

---

## Technical Architecture

### Module Structure

```
net_watch/breach/
├── __init__.py           # Module exports
├── breach_database.py    # Local breach metadata database
├── password_checker.py   # HIBP password checker (k-anonymity)
├── email_checker.py      # Email/domain/username/phone checker
├── formatter.py          # Output formatting (Rich tables, JSON)
├── cli.py               # CLI orchestrator and argument parsing
└── README.md            # This documentation
```

### Integration Points

1. **Hound Shell** (`net_watch/shell.py`)
   - `do_fetch()` method integrates with shell
   - Argument parsing and routing to CLI orchestrator

2. **CLI Orchestrator** (`breach/cli.py`)
   - Parses arguments using argparse
   - Routes to appropriate checker
   - Handles output formatting

3. **Checkers** (`password_checker.py`, `email_checker.py`)
   - Perform actual breach lookups
   - Return structured result dictionaries

4. **Formatter** (`formatter.py`)
   - Rich table formatting for visual output
   - JSON export for machine-readable results
   - Ethics banner display

---

## Dependencies

Required libraries (already in `requirements.txt`):

```
requests>=2.31.0   # For HIBP API calls
rich>=13.7.0       # For beautiful table formatting
```

Install with:
```bash
pip install -r requirements.txt
```

---

## Privacy & Security

### What Data is Stored?
**None.** This module:
- Does NOT store passwords
- Does NOT store email addresses
- Does NOT store query history
- Does NOT log searches (by default)

### What Data is Transmitted?
**Password checks only:**
- First 5 characters of SHA-1 password hash to HIBP API
- No other queries require network access (local database)

### What Data is Saved?
**Only when explicitly requested** with `--output`:
- Report files saved to current directory
- Filename includes query type and sanitized query value
- Format: `breach_report_{type}_{query}_{timestamp}.json`

---

## Legal & Compliance

### GDPR Compliance
- No personal data stored
- No tracking or profiling
- Users control their own queries
- Reports saved only on explicit request

### Intended Use
This tool is designed for:
- **Defensive security operations**
- **Educational purposes**
- **Authorized security assessments**
- **Personal account security checks**

### Prohibited Use
This tool must NOT be used for:
- Unauthorized access attempts
- Credential stuffing attacks
- Privacy violations
- Any illegal activities

---

## Limitations

### Password Checker
- Requires internet connection for HIBP API
- Only checks against known breach databases
- Not finding a password doesn't guarantee it's strong
- Very new breaches may not be included yet

### Email/Domain Checker
- Limited to 15 major public breaches
- Not comprehensive of all breaches
- Wildcard matches have lower confidence
- Cannot check specific email presence, only domain

### Username/Phone Checker
- Shows breaches that exposed this data type
- Cannot confirm specific username/phone inclusion
- Results are informational only

---

## Troubleshooting

### "No module named 'rich'" error
```bash
pip install rich
```

### "No module named 'requests'" error
```bash
pip install requests
```

### Password check fails with network error
- Check internet connection
- HIBP API may be temporarily unavailable
- Try again in a few minutes

### Email shows no breaches but should
- Local database only includes 15 major breaches
- Check domain spelling
- Some breaches may not be in our database

---

## Future Enhancements

Potential improvements for future versions:

1. **Expanded breach database**
   - Add more public breaches
   - Regular updates from public sources

2. **API integration options**
   - HIBP email API (requires API key)
   - DeHashed API (requires subscription)

3. **Batch checking**
   - Check multiple emails/passwords from file
   - Summary statistics across batch

4. **Monitoring mode**
   - Periodic automated checks
   - Alert on new breaches

5. **Integration with SIEM**
   - Export to common SIEM formats
   - Webhook notifications

---

## Credits

### Data Sources
- **Have I Been Pwned (HIBP)**: Troy Hunt's excellent service for password breach checking
- **Public breach disclosures**: Data from official breach notifications and security researchers

### Technologies
- **Rich library**: Beautiful terminal formatting
- **Requests**: HTTP library for API calls
- **Python argparse**: Argument parsing

---

## Version History

### v1.0.0 (2025-12-20)
- Initial release
- Password checking via HIBP k-anonymity API
- Email/domain/username/phone checking against local database
- 15 major breaches included
- Rich table and JSON output formats
- Full hound shell integration

---

## Contact & Support

For issues, suggestions, or questions about this module:
- Check hound documentation
- Review this README
- Ensure ethical use compliance

**Remember: Use responsibly. Protect privacy. Stay legal.**
