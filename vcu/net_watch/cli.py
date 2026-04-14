"""Command-line interface for vcu

This module coordinates all the network monitoring components:
- Parsers: Extract information from DNS, HTTP, and TCP packets
- Trackers: Keep track of devices, domains, connections, and browsing sessions
- Detectors: Identify suspicious behavior patterns (beaconing, tracking, anomalies)
"""

import click
import time
from net_watch.capture import PacketCapture
from net_watch.alerts import AlertManager, AlertLevel, Alert
from net_watch.parsers.dns import DNSParser
from net_watch.parsers.http import HTTPParser
from net_watch.parsers.tcp import TCPParser
from net_watch.parsers.payload import PayloadParser
from net_watch.tracking.device_tracker import DeviceTracker
from net_watch.tracking.domain_tracker import DomainTracker
from net_watch.tracking.connection_tracker import ConnectionTracker
from net_watch.tracking.session_tracker import SessionTracker
from net_watch.detectors.beaconing import BeaconingDetector
from net_watch.detectors.tracking import TrackingDetector
from net_watch.detectors.anomaly import AnomalyDetector


class NetworkMonitor:
    """Main network monitoring coordinator

    This class orchestrates all packet analysis components:
    1. Receives packets from PacketCapture
    2. Parses them with DNS/HTTP/TCP parsers
    3. Updates trackers with extracted data
    4. Runs detectors periodically to identify suspicious patterns
    """

    def __init__(self, verbose: bool = False, alerts_only: bool = False, show_all: bool = False, enable_ai: bool = False):
        # Alert system for displaying messages to user
        self.alert_manager = AlertManager(verbose=verbose, alerts_only=alerts_only)
        self.show_all = show_all  # Whether to display all traffic like Wireshark
        self.enable_ai = enable_ai  # Whether to enable AI analysis

        # Protocol parsers - extract information from packets
        self.dns_parser = DNSParser()      # DNS queries and responses
        self.http_parser = HTTPParser()    # HTTP requests and HTTPS connections
        self.tcp_parser = TCPParser()      # TCP connection data
        self.payload_parser = PayloadParser()  # Extract sensitive data from payloads

        # Trackers - maintain state about network activity
        self.device_tracker = DeviceTracker()            # Track devices on network
        self.domain_tracker = DomainTracker()            # Track domain access patterns
        self.connection_tracker = ConnectionTracker()    # Track TCP connections
        self.session_tracker = SessionTracker()          # Track website browsing context

        # Detectors - identify suspicious behavior patterns
        self.beaconing_detector = BeaconingDetector(     # Detect periodic automated communication
            self.domain_tracker,
            self.alert_manager
        )
        self.tracking_detector = TrackingDetector(       # Detect excessive third-party tracking
            self.domain_tracker,
            self.device_tracker,
            self.alert_manager
        )
        self.anomaly_detector = AnomalyDetector(         # Detect various anomalies (DGA, port scanning, etc.)
            self.connection_tracker,
            self.tcp_parser,
            self.dns_parser,
            self.alert_manager
        )

        # AI analysis engine (optional)
        self.ai_engine = None
        if enable_ai:
            from net_watch.ai_analysis import AIAnalysisEngine
            try:
                self.ai_engine = AIAnalysisEngine()
                self.alert_manager.info("AI analysis enabled - results will be saved after scan")
            except Exception as e:
                self.alert_manager.warning(f"AI analysis not available: {e}")

        # Timing for periodic detector runs
        self.packet_count = 0
        self.last_detector_run = time.time()

        # Reference to capture for AI analysis
        self.capture = None

    def handle_packet(self, packet):
        """Main packet handler - coordinates all parsing and analysis

        This is called for every packet captured. It:
        1. Optionally displays the packet (in --show-all mode)
        2. Runs all parsers on the packet
        3. Updates trackers with parsed data
        4. Periodically runs detectors to identify suspicious patterns
        """
        self.packet_count += 1

        # In show-all mode, display every packet (like Wireshark)
        if self.show_all:
            from scapy.all import IP, TCP, UDP, ARP
            summary = packet.summary()[:80]

            # Extract and display packet details
            if packet.haslayer(IP):
                src = packet[IP].src
                dst = packet[IP].dst

                if packet.haslayer(TCP):
                    sport = packet[TCP].sport
                    dport = packet[TCP].dport
                    # Don't print DNS/HTTP/HTTPS here (those are printed by specific handlers)
                    if dport not in [53, 80, 443] and sport not in [53, 80, 443]:
                        print(f"[TCP] {src}:{sport} → {dst}:{dport}")
                elif packet.haslayer(UDP):
                    sport = packet[UDP].sport
                    dport = packet[UDP].dport
                    if dport != 53 and sport != 53:  # DNS is handled by DNS parser
                        print(f"[UDP] {src}:{sport} → {dst}:{dport}")
            elif packet.haslayer(ARP):
                print(f"[ARP] {summary}")

        # Run all protocol parsers to extract relevant information
        dns_data = self.dns_parser.parse_packet(packet)
        http_data = self.http_parser.parse_packet(packet)
        tcp_data = self.tcp_parser.parse_packet(packet)

        # Parse payload for sensitive data
        payload_findings = self.payload_parser.parse_packet(packet)

        # Update trackers with parsed data
        if dns_data:
            self._handle_dns_data(dns_data)

        if http_data:
            self._handle_http_data(http_data)

        if tcp_data:
            self._handle_tcp_data(tcp_data)

        # Alert on sensitive data findings
        if payload_findings:
            self._handle_sensitive_data(payload_findings)

        # Run detectors periodically (not on every packet to save CPU)
        current_time = time.time()
        if current_time - self.last_detector_run > 10:  # Every 10 seconds
            self.run_detectors()
            self.last_detector_run = current_time

    def _handle_dns_data(self, data: dict):
        """Handle parsed DNS data

        DNS data helps us understand:
        - What domains devices are accessing
        - Which IPs correspond to which domains
        - Website browsing context
        """
        if data['type'] == 'dns_query':
            # Extract DNS query information
            domain = data['domain']
            device_ip = data['source_ip']
            timestamp = data['timestamp']

            # Update trackers with DNS query information
            self.domain_tracker.track_dns_query(domain, device_ip, timestamp)
            self.device_tracker.track_dns_query(device_ip, domain)

            # Track browsing session context (e.g., "while visiting linkedin.com")
            self.session_tracker.track_domain_access(device_ip, domain, is_http_request=False)

            # Display DNS queries in show-all mode
            if self.show_all:
                from net_watch.filters import is_local_mdns_domain
                domain_type = "mDNS" if is_local_mdns_domain(domain) else "DNS"
                print(f"[{domain_type}] {device_ip} → {domain}")

            # Show context in verbose mode
            elif self.alert_manager.verbose:
                context = self.session_tracker.get_context_for_domain(device_ip, domain)
                if context:
                    print(f"  DNS: {domain} ({context})")

        elif data['type'] == 'dns_response':
            # DNS response contains IP addresses for a domain
            domain = data['domain']
            ips = data['ips']

            # Store domain-to-IP mapping for later HTTPS connection analysis
            self.domain_tracker.track_dns_response(domain, ips)

    def _handle_http_data(self, data: dict):
        """Handle parsed HTTP data

        HTTP data shows us:
        - Plain HTTP requests (rare nowadays)
        - HTTPS connections (we see the IP, but content is encrypted)
        - Which websites devices are accessing
        """
        if data['type'] == 'http_request':
            # Plain HTTP request (unencrypted)
            host = data.get('host')
            device_ip = data['source_ip']
            method = data.get('method', 'GET')
            path = data.get('path', '/')

            if host:
                # Update trackers with HTTP request info
                self.domain_tracker.track_http_request(host, device_ip)
                self.device_tracker.track_http_request(device_ip, host)

                # Track browsing session context
                self.session_tracker.track_domain_access(device_ip, host, is_http_request=True)

                # Display in show-all mode
                if self.show_all:
                    print(f"[HTTP] {device_ip} → {method} {host}{path}")

                # Show context in verbose mode
                elif self.alert_manager.verbose:
                    context = self.session_tracker.get_context_for_domain(device_ip, host)
                    print(f"  HTTP: {host} ({context if context else 'new visit'})")

        elif data['type'] == 'https_connection':
            # HTTPS connection (encrypted, we only see IPs and ports)
            src_ip = data['source_ip']
            dst_ip = data['dest_ip']
            dst_port = data['dest_port']

            # Track HTTPS connections
            self.device_tracker.track_https_connection(src_ip, dst_ip)

            # Try to match IP to domain using DNS records
            domain = self.dns_parser.get_domain_for_ip(dst_ip)
            if domain != dst_ip:  # Successfully resolved IP to domain
                self.domain_tracker.track_http_request(domain, src_ip)

                # Display with domain name
                if self.show_all:
                    print(f"[HTTPS] {src_ip} → {domain}:{dst_port}")
            elif self.show_all:
                # Couldn't resolve to domain, show raw IP
                print(f"[TCP] {src_ip} → {dst_ip}:{dst_port} (encrypted)")

    def _handle_tcp_data(self, data: dict):
        """Handle parsed TCP data

        TCP data gives us low-level connection information:
        - Which devices are talking to which IPs/ports
        - Connection patterns and data transfer sizes
        """
        src_ip = data['source_ip']
        dst_ip = data['dest_ip']
        dst_port = data['dest_port']
        size = data['size']

        # Update trackers with TCP connection information
        self.device_tracker.track_connection(src_ip, dst_ip, dst_port, size)
        self.connection_tracker.track_connection(src_ip, dst_ip, dst_port, success=True)

    def _handle_sensitive_data(self, findings: list):
        """Handle sensitive data found in packet payloads."""
        for finding in findings:
            # Create critical alert for sensitive data exposure
            data_type_names = {
                'password': 'Password',
                'email': 'Email Address',
                'credit_card': 'Credit Card Number',
                'ssn': 'Social Security Number',
                'api_key': 'API Key',
                'bearer_token': 'Bearer Token',
                'jwt': 'JWT Token',
                'username': 'Username'
            }

            data_type_name = data_type_names.get(finding.data_type, finding.data_type)

            # Use CRITICAL for passwords, credit cards, SSNs, API keys
            # Use ALERT for emails, usernames, tokens
            if finding.data_type in ['password', 'credit_card', 'ssn', 'api_key']:
                level = AlertLevel.CRITICAL
            else:
                level = AlertLevel.ALERT

            self.alert_manager.add_alert(Alert(
                level=level,
                message=f"Sensitive data detected: {data_type_name} sent from {finding.source_ip} to {finding.dest_ip}",
                explanation=f"{data_type_name} transmitted in cleartext over {finding.protocol}. "
                           f"This is a serious security risk as the data can be intercepted.",
                technical_details=f"Value: {finding.value}\nContext: {finding.context}"
            ))

    def run_detectors(self):
        """Run all behavioral detectors

        Detectors analyze tracked data to identify suspicious patterns:
        - Beaconing: Periodic automated communication (e.g., malware calling home)
        - Tracking: Excessive third-party tracking cookies/requests
        - Anomalies: DGA domains, port scanning, unusual connection patterns
        """
        self.beaconing_detector.check_for_beaconing()
        self.tracking_detector.check_for_excessive_tracking()
        self.anomaly_detector.check_for_anomalies()

        # Cleanup old connections to prevent memory growth
        self.tcp_parser.cleanup_old_connections()

    def show_session_summary(self):
        """Show browsing session summary"""
        print("\n" + "=" * 60)
        print("Websites Visited:")
        print("=" * 60)

        # Get all devices that have sessions
        all_devices = set()
        for device_ip in self.session_tracker.active_sessions.keys():
            all_devices.add(device_ip)
        for device_ip in self.session_tracker.recent_visits.keys():
            all_devices.add(device_ip)

        if not all_devices:
            print("No websites detected (only saw raw IP traffic)")
            return

        for device_ip in all_devices:
            recent_sites = self.session_tracker.get_recent_websites(device_ip, limit=10)

            if recent_sites:
                # Get device info
                if self.device_tracker.devices.get(device_ip):
                    device = self.device_tracker.devices[device_ip]
                    print(f"\nDevice: {device_ip}")
                    print(f"  Websites visited:")
                    for i, site in enumerate(recent_sites, 1):
                        print(f"    {i}. {site}")

                    # Show session details
                    summary = self.session_tracker.get_session_summary(device_ip)
                    if summary.get('current_site'):
                        print(f"  Currently on: {summary['current_site']}")
                        if summary.get('third_party_count', 0) > 0:
                            print(f"    Loaded {summary['third_party_count']} third-party domains")

        print("=" * 60)

        # Show sensitive data findings if any
        sensitive_summary = self.payload_parser.get_summary()
        if sensitive_summary:
            print("\n" + "=" * 60)
            print("SENSITIVE DATA DETECTED:")
            print("=" * 60)
            for data_type, count in sensitive_summary.items():
                data_type_display = data_type.replace('_', ' ').title()
                print(f"  {data_type_display}: {count} instance(s)")
            print("\nWARNING: Sensitive data was transmitted in cleartext!")
            print("Check alerts above for details.")
            print("=" * 60)

    def run_ai_analysis(self):
        """Run AI analysis on captured data and save results"""
        if not self.ai_engine:
            self.alert_manager.warning("AI analysis not enabled. Use --ai flag to enable.")
            return

        self.alert_manager.info("Running AI analysis on scan results...")

        try:
            # Run full AI analysis
            results = self.ai_engine.run_full_analysis(self, save_report=True)

            print("\n" + "=" * 60)
            print("AI SECURITY ANALYSIS")
            print("=" * 60)
            print(results['ai_analysis'])
            print("\n" + "=" * 60)
            print(f"Full report saved to: {results.get('report_file', 'N/A')}")
            print(f"Raw data saved to: {results['scan_file']}")
            print("=" * 60)

        except Exception as e:
            self.alert_manager.error(f"AI analysis failed: {e}")
            import traceback
            traceback.print_exc()


def run_live_capture(iface, device=None, show_all=False, verbose=False, alerts_only=False, enable_ai=False):
    """Wrapper function to run live capture (called from shell)"""
    click.echo(f"vcu v0.1.0 - Live Network Monitor")
    click.echo("=" * 60)
    click.echo()

    # Create monitor
    monitor = NetworkMonitor(verbose=verbose, alerts_only=alerts_only, show_all=show_all, enable_ai=enable_ai)

    # Create custom summary callback that includes AI analysis
    def summary_callback_with_ai():
        monitor.show_session_summary()
        if enable_ai:
            monitor.run_ai_analysis()

    # Create capture engine
    capture = PacketCapture(
        alert_manager=monitor.alert_manager,
        interface=iface,
        filter_device=device,
        summary_callback=summary_callback_with_ai
    )

    # Store capture reference for AI analysis
    monitor.capture = capture

    # Register packet handler
    capture.register_handler(monitor.handle_packet)

    # Start capture
    capture.start_live_capture()


def run_pcap_analysis(pcap_file, device=None, show_all=False, verbose=False, alerts_only=False, enable_ai=False):
    """Wrapper function to run pcap analysis (called from shell)"""
    click.echo(f"vcu v0.1.0 - PCAP Analyzer")
    click.echo("=" * 60)
    click.echo()

    # Create monitor
    monitor = NetworkMonitor(verbose=verbose, alerts_only=alerts_only, show_all=show_all, enable_ai=enable_ai)

    # Create custom summary callback that includes AI analysis
    def summary_callback_with_ai():
        monitor.show_session_summary()
        if enable_ai:
            monitor.run_ai_analysis()

    # Create capture engine
    capture = PacketCapture(
        alert_manager=monitor.alert_manager,
        pcap_file=pcap_file,
        filter_device=device,
        summary_callback=summary_callback_with_ai
    )

    # Store capture reference for AI analysis
    monitor.capture = capture

    # Register packet handler
    capture.register_handler(monitor.handle_packet)

    # Analyze pcap
    capture.analyze_pcap()

    # Run detectors one final time
    monitor.run_detectors()


@click.command()
def cli():
    """
    vcu: Network monitoring tool with human-readable security analysis

    Type 'vcu' to enter interactive mode.
    """
    # Start the interactive shell
    from net_watch.shell import start_shell
    start_shell()


def main():
    """Main entry point"""
    try:
        cli()
    except KeyboardInterrupt:
        print("\n\nStopped by user.")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
