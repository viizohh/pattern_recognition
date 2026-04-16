"""Anomaly detection - identifies suspicious network behaviors"""

import time
from typing import List, Dict
from net_watch.tracking.connection_tracker import ConnectionTracker
from net_watch.parsers.tcp import TCPParser
from net_watch.parsers.dns import DNSParser
from net_watch.alerts import AlertManager
from net_watch.utils import format_duration, format_bytes
from net_watch.filters import (
    is_local_mdns_domain,
    is_ephemeral_port,
    is_well_known_cdn,
    should_ignore_entropy_alert
)


class AnomalyDetector:
    """Detects various network anomalies and suspicious behaviors"""

    def __init__(
        self,
        connection_tracker: ConnectionTracker,
        tcp_parser: TCPParser,
        dns_parser: DNSParser,
        alert_manager: AlertManager
    ):
        self.connection_tracker = connection_tracker
        self.tcp_parser = tcp_parser
        self.dns_parser = dns_parser
        self.alert_manager = alert_manager
        self.alerted_anomalies = set()
        self.last_check = time.time()

        # Thresholds
        self.idle_connection_threshold = 300  # 5 minutes
        self.long_connection_threshold = 3600  # 1 hour
        self.failed_connection_threshold = 10
        self.high_entropy_threshold = 4.0
        self.check_interval = 30  # seconds

    def check_for_anomalies(self):
        """Run all anomaly checks"""
        current_time = time.time()

        # Don't check too frequently
        if current_time - self.last_check < self.check_interval:
            return

        self.last_check = current_time

        self.check_long_lived_connections()
        self.check_idle_connections()
        self.check_failed_connections()
        self.check_high_entropy_domains()
        self.check_suspicious_ports()
        self.check_connection_bursts()

    def check_long_lived_connections(self):
        """Detect long-lived connections"""
        long_connections = self.tcp_parser.get_long_lived_connections(
            self.long_connection_threshold
        )

        for conn in long_connections:
            alert_key = f"long_conn_{conn.get_connection_key()}"
            if alert_key in self.alerted_anomalies:
                continue

            duration_str = format_duration(conn.get_duration())

            idle_time = time.time() - conn.last_seen
            if idle_time > 60:  # No activity in last minute
                self.alert_manager.warning(
                    f"Device {conn.src_ip} has a long-lived connection to {conn.dst_ip}:{conn.dst_port} ({duration_str}).",
                    explanation="Connection has been open for extended period with minimal activity. Could be legitimate service or suspicious.",
                    technical_details=f"Packets: {conn.packets}, Bytes: {format_bytes(conn.bytes_sent)}"
                )
                self.alerted_anomalies.add(alert_key)

    def check_idle_connections(self):
        """Detect idle but open connections"""
        idle_connections = self.tcp_parser.get_idle_connections(
            self.idle_connection_threshold
        )

        # Group by source IP to avoid spam
        idle_by_device = {}
        for conn in idle_connections:
            if conn.src_ip not in idle_by_device:
                idle_by_device[conn.src_ip] = []
            idle_by_device[conn.src_ip].append(conn)

        for device_ip, conns in idle_by_device.items():
            if len(conns) < 3:  # Only alert if multiple idle connections
                continue

            alert_key = f"idle_conns_{device_ip}"
            if alert_key in self.alerted_anomalies:
                continue

            self.alert_manager.info(
                f"Device {device_ip} has {len(conns)} idle connections open.",
                explanation="Multiple connections with no recent activity. Usually harmless but could indicate stalled connections."
            )
            self.alerted_anomalies.add(alert_key)

    def check_failed_connections(self):
        """Detect repeated failed connection attempts"""
        failed_targets = self.tcp_parser.get_failed_connection_targets()

        for ip, port, count in failed_targets:
            alert_key = f"failed_{ip}:{port}"
            if alert_key in self.alerted_anomalies:
                continue

            # CDNs often have retry logic, so use higher threshold
            if is_well_known_cdn(ip) and count < 20:
                continue

            self.alert_manager.warning(
                f"Repeated failed connections to {ip}:{port} ({count} attempts).",
                explanation="Multiple connection failures could indicate a misconfigured service, network issue, or scanning activity.",
                technical_details=f"Failed attempts: {count}"
            )
            self.alerted_anomalies.add(alert_key)

    def check_high_entropy_domains(self):
        """Detect domains with high entropy (potential DGA)"""
        high_entropy_domains = self.dns_parser.get_high_entropy_domains(
            self.high_entropy_threshold
        )

        for domain, entropy in high_entropy_domains[:5]:  # Top 5
            alert_key = f"entropy_{domain}"
            if alert_key in self.alerted_anomalies:
                continue

            # Skip if should be ignored (local services, CDNs, etc.)
            if should_ignore_entropy_alert(domain, entropy):
                continue

            # Filter out some false positives
            if any(tld in domain for tld in ['.com', '.net', '.org', '.io']):
                # Real TLD reduces suspicion
                if entropy < 4.5:
                    continue

            self.alert_manager.alert(
                f"Domain '{domain}' has unusually high randomness (entropy: {entropy:.2f}).",
                explanation="High entropy domains can indicate Domain Generation Algorithm (DGA) used by malware, but can also be legitimate CDN or service domains.",
                technical_details=f"Entropy: {entropy:.2f}, Queries: {self.dns_parser.get_domain_query_count(domain)}"
            )
            self.alerted_anomalies.add(alert_key)

    def check_suspicious_ports(self):
        """Detect suspicious port activity"""
        suspicious_ports = self.connection_tracker.get_suspicious_ports()

        for port, stats in suspicious_ports[:5]:  # Top 5
            # Skip ephemeral ports (client-side temporary ports)
            if is_ephemeral_port(port):
                continue

            alert_key = f"port_{port}"
            if alert_key in self.alerted_anomalies:
                continue

            # Build explanation based on what's suspicious
            reasons = []
            if stats['failure_rate'] > 0.5:
                reasons.append(f"{stats['failure_rate']*100:.0f}% failure rate")
            if stats['is_uncommon']:
                reasons.append("uncommon port")
            if stats['unique_sources'] > stats['unique_destinations'] * 3:
                reasons.append("scanning pattern detected")

            reason_str = ", ".join(reasons)

            self.alert_manager.warning(
                f"Suspicious activity on port {port}: {reason_str}.",
                explanation="Unusual port activity could indicate misconfiguration, scanning, or malicious behavior.",
                technical_details=f"Attempts: {stats['total_attempts']}, Sources: {stats['unique_sources']}, Destinations: {stats['unique_destinations']}"
            )
            self.alerted_anomalies.add(alert_key)

    def check_connection_bursts(self):
        """Detect sudden bursts of connections"""
        bursts = self.connection_tracker.get_burst_connections(
            window=10.0,
            threshold=30
        )

        for device_ip, rate in bursts:
            alert_key = f"burst_{device_ip}_{int(time.time() // 60)}"  # Per minute
            if alert_key in self.alerted_anomalies:
                continue

            self.alert_manager.warning(
                f"Device {device_ip} initiated {rate:.0f} connections/second.",
                explanation="Sudden connection bursts could indicate scanning, DDoS participation, or legitimate but unusual activity.",
                technical_details=f"Rate: {rate:.1f} conn/sec"
            )
            self.alerted_anomalies.add(alert_key)

    def detect_dns_tunneling(self) -> List[Dict]:
        """
        Detect potential DNS tunneling
        (unusually long queries, high query volume to single domain)
        """
        tunneling_suspects = []

        for domain, query_list in self.dns_parser.queries.items():
            if len(query_list) < 20:
                continue

            if len(domain) > 50:
                # Calculate average query rate
                if len(query_list) >= 2:
                    duration = query_list[-1] - query_list[0]
                    rate = len(query_list) / max(duration, 1)

                    if rate > 0.5:  # More than 0.5 queries per second
                        tunneling_suspects.append({
                            "domain": domain,
                            "query_count": len(query_list),
                            "domain_length": len(domain),
                            "query_rate": rate
                        })

        return tunneling_suspects

    def detect_port_scanning(self) -> List[Dict]:
        """
        Detect potential port scanning activity
        (many connections to different ports on same host)
        """
        from collections import defaultdict
        scans = []

        src_to_dst_ports = defaultdict(set)

        for conn in self.tcp_parser.get_active_connections():
            key = (conn.src_ip, conn.dst_ip)
            src_to_dst_ports[key].add(conn.dst_port)

        for (src_ip, dst_ip), ports in src_to_dst_ports.items():
            if len(ports) > 10:  # More than 10 different ports
                scans.append({
                    "source_ip": src_ip,
                    "dest_ip": dst_ip,
                    "ports_scanned": len(ports),
                    "ports": sorted(list(ports))[:20]  # First 20
                })

        return scans

    def get_anomaly_summary(self) -> dict:
        """Get summary of detected anomalies"""
        return {
            "total_anomalies_detected": len(self.alerted_anomalies),
            "long_lived_connections": len(self.tcp_parser.get_long_lived_connections()),
            "idle_connections": len(self.tcp_parser.get_idle_connections()),
            "failed_connection_targets": len(self.tcp_parser.get_failed_connection_targets()),
            "high_entropy_domains": len(self.dns_parser.get_high_entropy_domains()),
            "suspicious_ports": len(self.connection_tracker.get_suspicious_ports())
        }
