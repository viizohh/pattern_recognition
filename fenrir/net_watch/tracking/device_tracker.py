"""Device tracking module"""

import time
from typing import Dict, Set
from collections import defaultdict
from net_watch.utils import is_private_ip


class DeviceProfile:
    """Profile for a single device"""

    def __init__(self, ip: str):
        self.ip = ip
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.domains_contacted: Set[str] = set()
        self.ips_contacted: Set[str] = set()
        self.ports_used: Set[int] = set()
        self.outbound_connections = 0
        self.inbound_connections = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.dns_queries = 0
        self.http_requests = 0
        self.https_connections = 0
        self.protocols: Dict[str, int] = defaultdict(int)

    def update_activity(self):
        """Update last seen timestamp"""
        self.last_seen = time.time()

    def add_domain(self, domain: str):
        """Add a contacted domain"""
        self.domains_contacted.add(domain)
        self.update_activity()

    def add_ip(self, ip: str):
        """Add a contacted IP"""
        self.ips_contacted.add(ip)
        self.update_activity()

    def add_outbound_connection(self, dest_ip: str, dest_port: int, bytes_sent: int = 0):
        """Record an outbound connection"""
        self.outbound_connections += 1
        self.ips_contacted.add(dest_ip)
        self.ports_used.add(dest_port)
        self.bytes_sent += bytes_sent
        self.update_activity()

    def add_inbound_connection(self, src_ip: str, bytes_received: int = 0):
        """Record an inbound connection"""
        self.inbound_connections += 1
        self.bytes_received += bytes_received
        self.update_activity()

    def increment_protocol(self, protocol: str):
        """Increment protocol counter"""
        self.protocols[protocol] += 1

    def get_total_connections(self) -> int:
        """Get total connection count"""
        return self.outbound_connections + self.inbound_connections

    def get_unique_domains_count(self) -> int:
        """Get count of unique domains contacted"""
        return len(self.domains_contacted)

    def get_unique_ips_count(self) -> int:
        """Get count of unique IPs contacted"""
        return len(self.ips_contacted)


class DeviceTracker:
    """Tracks activity for all devices on the network"""

    def __init__(self):
        self.devices: Dict[str, DeviceProfile] = {}

    def get_or_create_device(self, ip: str) -> DeviceProfile:
        """Get or create a device profile"""
        if ip not in self.devices:
            self.devices[ip] = DeviceProfile(ip)
        return self.devices[ip]

    def track_connection(self, src_ip: str, dst_ip: str, dst_port: int, size: int = 0):
        """Track a connection between two IPs"""
        src_device = self.get_or_create_device(src_ip)
        dst_device = self.get_or_create_device(dst_ip)

        # Only track outbound connections from local devices
        if is_private_ip(src_ip):
            src_device.add_outbound_connection(dst_ip, dst_port, size)

        if is_private_ip(dst_ip):
            dst_device.add_inbound_connection(src_ip, size)

    def track_dns_query(self, src_ip: str, domain: str):
        """Track a DNS query from a device"""
        device = self.get_or_create_device(src_ip)
        device.add_domain(domain)
        device.dns_queries += 1
        device.increment_protocol("DNS")

    def track_http_request(self, src_ip: str, host: str):
        """Track an HTTP request from a device"""
        device = self.get_or_create_device(src_ip)
        device.add_domain(host)
        device.http_requests += 1
        device.increment_protocol("HTTP")

    def track_https_connection(self, src_ip: str, dst_ip: str):
        """Track an HTTPS connection from a device"""
        device = self.get_or_create_device(src_ip)
        device.add_ip(dst_ip)
        device.https_connections += 1
        device.increment_protocol("HTTPS")

    def get_all_devices(self) -> list:
        """Get all tracked devices"""
        return list(self.devices.values())

    def get_local_devices(self) -> list:
        """Get only local (private IP) devices"""
        return [device for device in self.devices.values() if is_private_ip(device.ip)]

    def get_most_active_devices(self, limit: int = 10) -> list:
        """Get the most active devices by connection count"""
        devices = sorted(
            self.devices.values(),
            key=lambda d: d.get_total_connections(),
            reverse=True
        )
        return devices[:limit]

    def get_device_summary(self, ip: str) -> dict:
        """Get a summary for a specific device"""
        device = self.devices.get(ip)
        if not device:
            return None

        return {
            "ip": device.ip,
            "first_seen": device.first_seen,
            "last_seen": device.last_seen,
            "total_connections": device.get_total_connections(),
            "outbound_connections": device.outbound_connections,
            "inbound_connections": device.inbound_connections,
            "unique_domains": device.get_unique_domains_count(),
            "unique_ips": device.get_unique_ips_count(),
            "dns_queries": device.dns_queries,
            "http_requests": device.http_requests,
            "https_connections": device.https_connections,
            "bytes_sent": device.bytes_sent,
            "bytes_received": device.bytes_received,
        }
