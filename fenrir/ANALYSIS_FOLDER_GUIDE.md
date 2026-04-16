# Analysis Folder Guide

## Overview

When you run Fenrir with the `--ai` flag, all analysis results are automatically saved to an organized `./analysis/` folder structure.

## Folder Structure

```
./analysis/
├── raw_data/          # JSON scan data files
├── reports/           # Full AI analysis reports (Markdown)
└── summaries/         # Quick summary files (Text)
```

### `/raw_data/`
Contains the complete scan data exported to JSON format.

**Files:** `scan_YYYYMMDD_HHMMSS.json`

**Contents:**
- Scan metadata (timestamp, duration, packet count)
- All alerts detected
- Device profiles (IPs, connections, traffic stats)
- Domain profiles (queries, timing, relationships)
- Connection statistics
- Session information

**Use for:**
- Re-analyzing with different AI prompts
- Custom data processing scripts
- Compliance documentation
- Incident response evidence

### `/reports/`
Contains full AI security analysis reports in Markdown format.

**Files:** `analysis_YYYYMMDD_HHMMSS.md`

**Contents:**
- Threat summary with risk level
- Detailed suspicious pattern analysis
- Device risk assessments
- Domain risk assessments
- Correlation analysis
- Actionable recommendations (immediate, short-term, long-term)

**Use for:**
- Comprehensive security review
- Sharing with security team
- Management reports
- Compliance audits

### `/summaries/`
Contains quick summary files in plain text format.

**Files:** `summary_YYYYMMDD_HHMMSS.txt`

**Contents:**
- Timestamp and file references
- First 30 lines of AI analysis (threat summary + key findings)
- Link to full report

**Use for:**
- Quick overview without opening full report
- Terminal viewing (`cat summary_*.txt`)
- Email alerts / notifications
- Dashboard displays

## Usage Examples

### Basic PCAP Analysis with AI
```bash
fenrir
fenrir> sniff pcap capture.pcap --ai
```

**Result:**
```
./analysis/
├── raw_data/scan_20260414_180530.json
├── reports/analysis_20260414_180530.md
└── summaries/summary_20260414_180530.txt
```

### Live Capture with AI
```bash
fenrir
fenrir> sniff live --iface en0 --ai
# Press Ctrl+C to stop
```

**Result:**
- Same folder structure
- Files timestamped when analysis completes
- Scan duration based on capture time

## Viewing Results

### Full Report (Markdown)
```bash
# Use your favorite markdown viewer
open analysis/reports/analysis_20260414_180530.md

# Or view in terminal with markdown tools
mdcat analysis/reports/analysis_20260414_180530.md
glow analysis/reports/analysis_20260414_180530.md

# Or just cat it
cat analysis/reports/analysis_20260414_180530.md
```

### Quick Summary (Text)
```bash
cat analysis/summaries/summary_20260414_180530.txt
```

### Raw Data (JSON)
```bash
# Pretty print JSON
jq . analysis/raw_data/scan_20260414_180530.json

# Or view specific sections
jq '.alerts' analysis/raw_data/scan_20260414_180530.json
jq '.devices' analysis/raw_data/scan_20260414_180530.json
```

## File Naming Convention

All files use consistent timestamp naming:
- Format: `YYYYMMDD_HHMMSS`
- Example: `20260414_180530` = April 14, 2026 at 6:05:30 PM
- Matching timestamps = same scan

To find all files from a specific scan:
```bash
ls analysis/*/* | grep 20260414_180530
```

## Automated Workflows

### Daily Security Report
```bash
#!/bin/bash
# Daily automated scan and report

fenrir <<EOF
sniff pcap /captures/daily_$(date +%Y%m%d).pcap --ai
quit
EOF

# Email the summary
mail -s "Daily Security Summary" security@company.com < \
  analysis/summaries/summary_$(date +%Y%m%d)_*.txt
```

### Alert on Critical Findings
```bash
#!/bin/bash
# Check for CRITICAL threats in latest report

LATEST_REPORT=$(ls -t analysis/reports/*.md | head -1)

if grep -q "CRITICAL" "$LATEST_REPORT"; then
    echo "CRITICAL threat detected!" | mail -s "URGENT: Security Alert" security@company.com
    cat "$LATEST_REPORT" | mail -s "Security Report Details" security@company.com
fi
```

### Bulk Analysis
```bash
#!/bin/bash
# Analyze all PCAP files in directory

for pcap in /captures/*.pcap; do
    echo "Analyzing $pcap..."
    fenrir <<EOF
sniff pcap "$pcap" --ai
quit
EOF
done

echo "All analyses complete. Check ./analysis/ folder."
```

## Data Retention

### Recommended Retention Periods
- **Raw Data:** 90 days (compliance/forensics)
- **Reports:** 1 year (trend analysis)
- **Summaries:** 30 days (quick reference)

### Cleanup Script
```bash
#!/bin/bash
# Clean up old analysis files

# Remove raw data older than 90 days
find analysis/raw_data/ -name "*.json" -mtime +90 -delete

# Remove reports older than 1 year
find analysis/reports/ -name "*.md" -mtime +365 -delete

# Remove summaries older than 30 days
find analysis/summaries/ -name "*.txt" -mtime +30 -delete

echo "Cleanup complete."
```

## Integration with Other Tools

### Export to SIEM
```python
import json
import syslog

with open('analysis/raw_data/scan_20260414_180530.json') as f:
    data = json.load(f)

for alert in data['alerts']:
    syslog.syslog(syslog.LOG_ALERT, f"Fenrir: {alert['message']}")
```

### Generate PDF Report
```bash
# Using pandoc
pandoc analysis/reports/analysis_20260414_180530.md \
    -o analysis/reports/analysis_20260414_180530.pdf

# Or with markdown-pdf
markdown-pdf analysis/reports/analysis_20260414_180530.md
```

### Dashboard Integration
```javascript
// Read latest summary for dashboard widget
const fs = require('fs');
const latestSummary = fs.readFileSync(
    'analysis/summaries/summary_latest.txt',
    'utf8'
);
dashboard.updateWidget('security', latestSummary);
```

## Best Practices

### 1. Organize by Date
```bash
# Create date-based folders for long-term storage
mkdir -p archive/$(date +%Y/%m)
mv analysis/reports/analysis_$(date +%Y%m)*.md archive/$(date +%Y/%m)/
```

### 2. Version Control Reports (Not Raw Data)
```bash
# Reports can be versioned, raw data is too large
git add analysis/reports/*.md
git commit -m "Daily security reports - $(date +%Y-%m-%d)"
```

### 3. Encrypt Sensitive Data
```bash
# Encrypt raw data containing sensitive info
gpg -c analysis/raw_data/scan_20260414_180530.json
rm analysis/raw_data/scan_20260414_180530.json
```

### 4. Symbolic Links for Latest
```bash
# Create symbolic links to latest files
ln -sf analysis/reports/analysis_$(ls -t analysis/reports/*.md | head -1 | xargs basename) analysis/reports/latest.md
ln -sf analysis/summaries/summary_$(ls -t analysis/summaries/*.txt | head -1 | xargs basename) analysis/summaries/latest.txt
```

## Troubleshooting

### Folder Not Created
**Issue:** `./analysis/` folder doesn't exist

**Solution:** Run Fenrir with `--ai` flag at least once:
```bash
fenrir
fenrir> sniff pcap any_file.pcap --ai
```

### Permission Denied
**Issue:** Can't write to analysis folder

**Solution:** Check permissions:
```bash
chmod 755 analysis
chmod 755 analysis/*
```

### Out of Disk Space
**Issue:** Too many analysis files

**Solution:** Run cleanup script or manually remove old files:
```bash
rm analysis/raw_data/scan_202604*.json
```

## File Size Estimates

- **Raw Data JSON:** 10KB - 5MB (depends on scan duration)
- **Full Report MD:** 5KB - 50KB (depends on AI findings)
- **Summary TXT:** 1KB - 5KB

For a typical 5-minute scan:
- Raw Data: ~100KB
- Report: ~15KB
- Summary: ~2KB
- **Total: ~120KB per scan**

## Security Considerations

1. **Sensitive Data:** Raw JSON contains all network traffic metadata including IPs, domains, potential credentials
2. **Access Control:** Restrict `analysis/` folder to security team only
3. **Encryption:** Encrypt folder on disk or use encrypted filesystem
4. **Audit Trail:** Log who accesses analysis files
5. **Retention:** Follow your organization's data retention policies

---

**Questions?** Check the main Fenrir documentation or run `fenrir` and type `help`
