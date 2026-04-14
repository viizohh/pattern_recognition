"""
AI-powered analysis engine for network security patterns.

This module provides intelligent analysis of network scan results,
using AI to identify suspicious patterns, correlate alerts, and
provide actionable security insights.
"""

import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path


class ScanResultsExporter:
    """Exports scan results to structured format for AI analysis."""

    def __init__(self, output_dir: str = "./scan_results"):
        """Initialize exporter with output directory."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def export_to_json(self, monitor, filename: Optional[str] = None) -> str:
        """
        Export current monitoring state to JSON file.

        Args:
            monitor: NetworkMonitor instance
            filename: Optional custom filename

        Returns:
            Path to the exported JSON file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.json"

        filepath = self.output_dir / filename

        # Collect all scan data
        scan_data = {
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "scan_duration": monitor.capture.total_time if hasattr(monitor, 'capture') else 0,
                "total_packets": monitor.capture.packet_count if hasattr(monitor, 'capture') else 0
            },
            "alerts": self._export_alerts(monitor.alert_manager),
            "devices": self._export_devices(monitor.device_tracker),
            "domains": self._export_domains(monitor.domain_tracker),
            "connections": self._export_connections(monitor.connection_tracker),
            "sessions": self._export_sessions(monitor.session_tracker)
        }

        # Write to file
        with open(filepath, 'w') as f:
            json.dump(scan_data, f, indent=2, default=str)

        return str(filepath)

    def _export_alerts(self, alert_manager) -> List[Dict]:
        """Export alerts to structured format."""
        alerts_data = []
        for alert in alert_manager.alerts:
            alerts_data.append({
                "level": alert.level.name,
                "timestamp": alert.timestamp,
                "message": alert.message,
                "explanation": alert.explanation,
                "technical_details": alert.technical_details
            })
        return alerts_data

    def _export_devices(self, device_tracker) -> List[Dict]:
        """Export device profiles to structured format."""
        devices_data = []
        for ip, profile in device_tracker.devices.items():
            devices_data.append({
                "ip": ip,
                "first_seen": profile.first_seen,
                "last_seen": profile.last_seen,
                "domains_contacted": list(profile.domains_contacted),
                "ips_contacted": list(profile.ips_contacted),
                "ports_used": list(profile.ports_used),
                "outbound_connections": profile.outbound_connections,
                "inbound_connections": profile.inbound_connections,
                "bytes_sent": profile.bytes_sent,
                "bytes_received": profile.bytes_received,
                "dns_queries": profile.dns_queries,
                "http_requests": profile.http_requests,
                "https_connections": profile.https_connections,
                "protocols": dict(profile.protocols)
            })
        return devices_data

    def _export_domains(self, domain_tracker) -> List[Dict]:
        """Export domain profiles to structured format."""
        domains_data = []
        for domain, profile in domain_tracker.domains.items():
            domains_data.append({
                "domain": domain,
                "first_seen": profile.first_seen,
                "last_seen": profile.last_seen,
                "query_count": profile.query_count,
                "request_count": profile.request_count,
                "query_timestamps": profile.query_timestamps,
                "devices": list(profile.devices),
                "resolved_ips": list(profile.resolved_ips),
                "is_third_party": profile.is_third_party,
                "parent_domain": profile.parent_domain
            })
        return domains_data

    def _export_connections(self, connection_tracker) -> Dict:
        """Export connection statistics to structured format."""
        stats = connection_tracker.stats
        return {
            "total_connections": stats.total_connections,
            "active_connections": stats.active_connections,
            "failed_connections": stats.failed_connections,
            "connection_start_times": stats.connection_start_times,
            "connection_durations": stats.connection_durations,
            "ports_accessed": {str(k): v for k, v in stats.ports_accessed.items()},
            "connection_pairs": {f"{k[0]}->{k[1]}": v for k, v in stats.connection_pairs.items()}
        }

    def _export_sessions(self, session_tracker) -> Dict:
        """Export session information to structured format."""
        sessions_data = {}

        # Export active sessions
        for device_ip, sessions in session_tracker.active_sessions.items():
            active_session_data = []
            for session in sessions:
                if session.is_active():
                    active_session_data.append({
                        "primary_domain": session.primary_domain,
                        "start_time": session.start_time,
                        "last_activity": session.last_activity,
                        "third_party_domains": list(session.third_party_domains),
                        "connection_count": session.connection_count
                    })

            if active_session_data:
                sessions_data[device_ip] = {
                    "active_sessions": active_session_data,
                    "recent_visits": [
                        {"domain": domain, "timestamp": ts}
                        for domain, ts in session_tracker.recent_visits.get(device_ip, [])
                    ]
                }

        return sessions_data


class AIPatternAnalyzer:
    """Analyzes scan results using AI to identify suspicious patterns."""

    def __init__(self, api_key: Optional[str] = None):
        """
        Initialize AI analyzer.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
        """
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')
        if not self.api_key:
            raise ValueError(
                "Anthropic API key required. Set ANTHROPIC_API_KEY environment variable "
                "or pass api_key parameter."
            )

    def analyze_scan_results(self, json_file_path: str) -> Dict[str, Any]:
        """
        Analyze scan results from JSON file using Claude AI.

        Args:
            json_file_path: Path to JSON file containing scan results

        Returns:
            Dictionary containing AI analysis results
        """
        # Load scan data
        with open(json_file_path, 'r') as f:
            scan_data = json.load(f)

        # Prepare analysis prompt
        prompt = self._build_analysis_prompt(scan_data)

        # Call Claude API
        analysis = self._call_claude_api(prompt)

        return {
            "scan_file": json_file_path,
            "analysis_timestamp": datetime.now().isoformat(),
            "ai_analysis": analysis,
            "scan_metadata": scan_data.get("metadata", {})
        }

    def _build_analysis_prompt(self, scan_data: Dict) -> str:
        """Build comprehensive analysis prompt for Claude."""

        # Summarize key metrics
        metadata = scan_data.get("metadata", {})
        alerts = scan_data.get("alerts", [])
        devices = scan_data.get("devices", [])
        domains = scan_data.get("domains", [])
        connections = scan_data.get("connections", {})

        prompt = f"""You are a cybersecurity expert analyzing network traffic scan results.
Your task is to identify suspicious patterns, security risks, and provide actionable recommendations.

# SCAN OVERVIEW
- Scan Duration: {metadata.get('scan_duration', 'unknown')} seconds
- Total Packets: {metadata.get('total_packets', 'unknown')}
- Devices Detected: {len(devices)}
- Domains Contacted: {len(domains)}
- Total Connections: {connections.get('total_connections', 'unknown')}
- Failed Connections: {connections.get('failed_connections', 'unknown')}

# ALERTS DETECTED
{self._format_alerts(alerts)}

# DEVICE ACTIVITY
{self._format_devices(devices)}

# DOMAIN ANALYSIS
{self._format_domains(domains)}

# CONNECTION PATTERNS
{self._format_connections(connections)}

# ANALYSIS TASKS

Please provide a comprehensive security analysis including:

1. **THREAT SUMMARY**: Overall risk level (LOW/MEDIUM/HIGH/CRITICAL) with justification

2. **SUSPICIOUS PATTERNS**: Identify any concerning behaviors such as:
   - Beaconing or C2 communication patterns
   - Data exfiltration indicators
   - Port scanning or reconnaissance activity
   - Connections to known malicious domains/IPs
   - Unusual traffic volumes or timing patterns
   - DGA (Domain Generation Algorithm) domains
   - Excessive third-party tracking

3. **DEVICE RISK ASSESSMENT**: For each device, assess:
   - Risk level and concerning behaviors
   - Most suspicious connections
   - Recommended actions

4. **DOMAIN RISK ASSESSMENT**: Flag suspicious domains including:
   - Known malicious domains
   - High-entropy/DGA domains
   - Unusual geographic locations or ASNs
   - Domains with beaconing patterns

5. **CORRELATION ANALYSIS**: Identify related suspicious activities across:
   - Multiple devices
   - Multiple domains
   - Temporal patterns
   - Attack chain indicators

6. **ACTIONABLE RECOMMENDATIONS**: Prioritized list of actions to take:
   - Immediate actions (critical threats)
   - Short-term actions (investigation needed)
   - Long-term actions (security improvements)

Format your response in clear sections with specific evidence from the scan data.
Be precise about threat indicators and avoid false positives where possible.
"""

        return prompt

    def _format_alerts(self, alerts: List[Dict]) -> str:
        """Format alerts for prompt."""
        if not alerts:
            return "No alerts detected."

        alert_text = []
        for alert in alerts[:20]:  # Limit to prevent prompt overflow
            alert_text.append(
                f"[{alert['level']}] {alert['message']}\n"
                f"  Details: {alert.get('technical_details', 'N/A')}"
            )

        if len(alerts) > 20:
            alert_text.append(f"... and {len(alerts) - 20} more alerts")

        return "\n".join(alert_text)

    def _format_devices(self, devices: List[Dict]) -> str:
        """Format device information for prompt."""
        if not devices:
            return "No devices detected."

        device_text = []
        for device in devices[:10]:  # Limit to prevent prompt overflow
            device_text.append(
                f"Device {device['ip']}:\n"
                f"  - Domains contacted: {len(device['domains_contacted'])}\n"
                f"  - Outbound connections: {device['outbound_connections']}\n"
                f"  - Bytes sent/received: {device['bytes_sent']}/{device['bytes_received']}\n"
                f"  - DNS queries: {device['dns_queries']}, HTTP: {device['http_requests']}, HTTPS: {device['https_connections']}\n"
                f"  - Ports used: {device['ports_used'][:20]}"
            )

        if len(devices) > 10:
            device_text.append(f"... and {len(devices) - 10} more devices")

        return "\n".join(device_text)

    def _format_domains(self, domains: List[Dict]) -> str:
        """Format domain information for prompt."""
        if not domains:
            return "No domains detected."

        # Sort by query count to highlight most contacted domains
        sorted_domains = sorted(domains, key=lambda x: x['query_count'], reverse=True)

        domain_text = []
        for domain in sorted_domains[:30]:  # Show top 30 domains
            is_third_party = " (3rd party)" if domain.get('is_third_party') else ""
            domain_text.append(
                f"{domain['domain']}{is_third_party}: "
                f"{domain['query_count']} queries, "
                f"{len(domain['devices'])} devices, "
                f"IPs: {domain['resolved_ips'][:3]}"
            )

        if len(domains) > 30:
            domain_text.append(f"... and {len(domains) - 30} more domains")

        return "\n".join(domain_text)

    def _format_connections(self, connections: Dict) -> str:
        """Format connection statistics for prompt."""
        if not connections:
            return "No connection data available."

        conn_text = [
            f"Total: {connections.get('total_connections', 0)}",
            f"Active: {connections.get('active_connections', 0)}",
            f"Failed: {connections.get('failed_connections', 0)}",
            f"Ports accessed: {len(connections.get('ports_accessed', {}))}"
        ]

        # Show top ports
        ports = connections.get('ports_accessed', {})
        if ports:
            top_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]
            conn_text.append(f"Top ports: {', '.join([f'{k}({v})' for k, v in top_ports])}")

        return ", ".join(conn_text)

    def _call_claude_api(self, prompt: str) -> str:
        """
        Call Claude API with the analysis prompt.

        Args:
            prompt: Analysis prompt

        Returns:
            AI analysis response
        """
        try:
            import anthropic
        except ImportError:
            raise ImportError(
                "anthropic package required for AI analysis. "
                "Install with: pip install anthropic"
            )

        client = anthropic.Anthropic(api_key=self.api_key)

        message = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=4096,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        return message.content[0].text


class AIAnalysisEngine:
    """Main AI analysis engine coordinating all AI-powered features."""

    def __init__(self, output_dir: str = "./scan_results", api_key: Optional[str] = None):
        """
        Initialize AI analysis engine.

        Args:
            output_dir: Directory for scan results
            api_key: Anthropic API key
        """
        self.exporter = ScanResultsExporter(output_dir)
        self.analyzer = AIPatternAnalyzer(api_key)
        self.output_dir = Path(output_dir)

    def run_full_analysis(self, monitor, save_report: bool = True) -> Dict[str, Any]:
        """
        Run complete AI analysis pipeline on current monitor state.

        Args:
            monitor: NetworkMonitor instance
            save_report: Whether to save analysis report to file

        Returns:
            Dictionary containing full analysis results
        """
        # Export scan results to JSON
        json_file = self.exporter.export_to_json(monitor)

        # Run AI analysis
        analysis = self.analyzer.analyze_scan_results(json_file)

        # Save report if requested
        if save_report:
            report_file = self._save_analysis_report(analysis)
            analysis['report_file'] = report_file

        return analysis

    def _save_analysis_report(self, analysis: Dict) -> str:
        """Save AI analysis report to markdown file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = self.output_dir / f"ai_analysis_{timestamp}.md"

        with open(report_file, 'w') as f:
            f.write("# Network Security AI Analysis Report\n\n")
            f.write(f"**Generated:** {analysis['analysis_timestamp']}\n\n")
            f.write(f"**Scan File:** {analysis['scan_file']}\n\n")
            f.write("---\n\n")
            f.write(analysis['ai_analysis'])

        return str(report_file)
