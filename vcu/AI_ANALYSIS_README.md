# AI-Powered Security Analysis for VCU

## Overview

VCU now includes an AI-powered analysis feature that uses Claude to identify suspicious network patterns and provide actionable security insights. After capturing network traffic, the AI analyzes all collected data to detect threats that might not be caught by traditional rule-based detection.

## Features

The AI analysis engine provides:

- **Threat Classification**: Automatically categorizes detected threats (malware, data exfiltration, port scanning, etc.)
- **Risk Assessment**: Assigns risk levels (LOW/MEDIUM/HIGH/CRITICAL) to devices and domains
- **Pattern Recognition**: Identifies complex attack patterns across multiple data points
- **Correlation Analysis**: Links related suspicious activities across devices and time
- **Actionable Recommendations**: Provides specific, prioritized steps to address threats
- **False Positive Reduction**: Uses context to reduce alert fatigue

## Setup

### 1. Install Requirements

```bash
pip install -r requirements.txt
```

This will install the `anthropic` Python package required for AI analysis.

### 2. Set API Key

Get your Anthropic API key from https://console.anthropic.com/ and set it as an environment variable:

```bash
export ANTHROPIC_API_KEY='your-api-key-here'
```

Or add it to your shell configuration (~/.bashrc, ~/.zshrc, etc.):

```bash
echo 'export ANTHROPIC_API_KEY="your-api-key-here"' >> ~/.bashrc
source ~/.bashrc
```

## Usage

### Live Capture with AI Analysis

```bash
vcu
vcu> sniff live --iface en0 --ai
```

### PCAP Analysis with AI

```bash
vcu
vcu> sniff pcap capture.pcap --ai
```

### Combined Options

```bash
# Show all traffic AND get AI analysis
vcu> sniff live --iface en0 --show-all --ai

# Analyze specific device with AI
vcu> sniff live --iface en0 --device 192.168.1.100 --ai

# Verbose mode with AI
vcu> sniff pcap suspicious.pcap --verbose --ai
```

## How It Works

### 1. Data Collection

During network capture, VCU collects:
- DNS queries and responses
- HTTP/HTTPS connections
- TCP connection patterns
- Device behaviors
- Domain access patterns
- Connection statistics

### 2. Data Export

When capture stops (Ctrl+C), if `--ai` flag is enabled:
- All collected data is exported to a JSON file in `./scan_results/`
- JSON includes metadata, alerts, device profiles, domain profiles, and connection stats

### 3. AI Analysis

The JSON data is sent to Claude with a comprehensive security analysis prompt that asks for:

- **Threat Summary**: Overall risk assessment
- **Suspicious Patterns**: Beaconing, C2 communication, data exfiltration, port scanning, DGA domains
- **Device Risk Assessment**: Per-device analysis with specific concerns
- **Domain Risk Assessment**: Flagging malicious or suspicious domains
- **Correlation Analysis**: Multi-stage attacks and related activities
- **Actionable Recommendations**: Prioritized list of immediate, short-term, and long-term actions

### 4. Report Generation

AI analysis is displayed in the terminal and saved to:
- **JSON file**: `./scan_results/scan_results_TIMESTAMP.json` (raw data)
- **Markdown report**: `./scan_results/ai_analysis_TIMESTAMP.md` (AI analysis)

## Example Output

```
============================================================
AI SECURITY ANALYSIS
============================================================

# THREAT SUMMARY
Risk Level: HIGH

Multiple indicators suggest potential malware activity on device 192.168.1.100,
including beaconing behavior to suspicious domains and connections to known
C2 infrastructure.

# SUSPICIOUS PATTERNS

1. Beaconing Detection:
   - Domain: api-check.example.com
   - Pattern: Contacted every 60 seconds for 10 minutes
   - Risk: Potential C2 communication channel

2. High-Entropy Domain:
   - Domain: x8j3k2m9q1.net
   - Shannon entropy: 4.2 (DGA-like)
   - Risk: Possible domain generation algorithm

3. Port Scanning:
   - Source: 192.168.1.100
   - Target: 10.0.0.50
   - Ports scanned: 15 ports in 2 seconds
   - Risk: Reconnaissance activity

# DEVICE RISK ASSESSMENT

Device 192.168.1.100: HIGH RISK
  - Contacted 5 suspicious domains
  - Unusual outbound traffic volume (50MB in 5 minutes)
  - Multiple failed connection attempts
  - Recommended action: Isolate and investigate immediately

# ACTIONABLE RECOMMENDATIONS

IMMEDIATE ACTIONS:
1. Isolate device 192.168.1.100 from network
2. Run full malware scan with updated definitions
3. Check for unauthorized processes/services

SHORT-TERM ACTIONS:
1. Monitor x8j3k2m9q1.net for additional connections
2. Review firewall logs for related activity
3. Check other devices for similar patterns

LONG-TERM ACTIONS:
1. Implement DNS filtering to block DGA domains
2. Deploy EDR solution on endpoints
3. Conduct security awareness training

============================================================
Full report saved to: ./scan_results/ai_analysis_20260412_143052.md
Raw data saved to: ./scan_results/scan_results_20260412_143052.json
============================================================
```

## Architecture

### Module Structure

```
net_watch/
  └── ai_analysis.py
      ├── ScanResultsExporter     # Exports monitoring data to JSON
      ├── AIPatternAnalyzer       # Calls Claude API for analysis
      └── AIAnalysisEngine        # Coordinates export + analysis
```

### Integration Points

AI analysis integrates with:
- **NetworkMonitor**: Main coordinator (cli.py:35)
- **AlertManager**: Existing alert system (alerts.py)
- **Device/Domain/Connection Trackers**: Data sources
- **PacketCapture**: Triggers analysis on capture end

## Data Privacy

- All analysis is done via Anthropic's Claude API
- Network data is only sent to Anthropic's servers when `--ai` is enabled
- Local JSON files contain raw scan data - secure them appropriately
- API calls are made over HTTPS
- Consider data sensitivity before enabling AI analysis on production networks

## Cost Considerations

AI analysis uses Claude's API which has usage costs:
- Typical analysis: ~$0.01-0.05 per scan (depending on data volume)
- Uses Claude 3.5 Sonnet model for optimal price/performance
- Larger scans (more devices/domains) cost more due to longer prompts
- Monitor your usage at https://console.anthropic.com/

## Troubleshooting

### "AI analysis not available: Anthropic API key required"

**Solution**: Set your API key:
```bash
export ANTHROPIC_API_KEY='your-key-here'
```

### "AI analysis failed: anthropic package not found"

**Solution**: Install requirements:
```bash
pip install anthropic
```

### JSON files are very large

**Cause**: Long captures with many packets generate large JSON files.

**Solution**:
- Use shorter capture periods
- Filter to specific devices with `--device`
- The AI analyzer automatically truncates very large datasets

### Analysis is slow

**Cause**: Large scans require more API processing time.

**Solution**:
- Analyze shorter time windows
- Filter traffic to specific devices
- Typical analysis takes 10-30 seconds

## Advanced Usage

### Analyzing Existing JSON Files

You can manually analyze previously exported JSON files:

```python
from net_watch.ai_analysis import AIPatternAnalyzer

analyzer = AIPatternAnalyzer(api_key='your-key')
results = analyzer.analyze_scan_results('scan_results/scan_results_20260412_143052.json')
print(results['ai_analysis'])
```

### Customizing Analysis Prompts

Edit `net_watch/ai_analysis.py:_build_analysis_prompt()` to customize:
- Focus areas (e.g., emphasize DLP over malware)
- Output format
- Risk scoring criteria
- Industry-specific threats

### Batch Analysis

Analyze multiple PCAP files:

```bash
for pcap in *.pcap; do
    echo "Analyzing $pcap..."
    echo "sniff pcap $pcap --ai" | vcu
done
```

## Security Best Practices

1. **Secure API Keys**: Never commit API keys to version control
2. **Network Isolation**: Run VCU from a monitoring network segment
3. **Data Retention**: Securely delete old JSON/report files
4. **Access Control**: Restrict access to scan_results directory
5. **Validation**: Always verify AI recommendations before taking action
6. **Logging**: Keep audit logs of when AI analysis is performed

## Limitations

- AI analysis is not a replacement for human security expertise
- May produce false positives on legitimate but unusual traffic
- Cannot decrypt encrypted traffic (only analyzes metadata)
- Relies on patterns seen in training data (knowledge cutoff: January 2025)
- Effectiveness depends on scan data quality and volume

## Future Enhancements

Planned features:
- Real-time AI analysis during live capture
- Integration with threat intelligence feeds
- Historical baseline learning
- Automated response actions
- Custom model fine-tuning
- Multi-scan correlation analysis

## Support

For issues or questions:
- Check this README first
- Review logs in scan_results directory
- Test with sample PCAP files
- Ensure API key is valid and has credits

## License

Same as VCU main project.
