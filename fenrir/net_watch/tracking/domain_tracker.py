"""Domain tracking module"""

import time
from typing import Dict, Set, List
from collections import defaultdict


class DomainProfile:
    """Profile for a single domain"""

    def __init__(self, domain: str):
        self.domain = domain
        self.first_seen = time.time()
        self.last_seen = self.first_seen
        self.query_count = 0
        self.request_count = 0
        self.query_timestamps: List[float] = []
        self.devices: Set[str] = set()  # IPs that contacted this domain
        self.resolved_ips: Set[str] = set()
        self.is_third_party = False
        self.parent_domain = None  # The "main" domain this was loaded from

    def add_query(self, device_ip: str, timestamp: float = None):
        """Record a DNS query for this domain"""
        if timestamp is None:
            timestamp = time.time()

        self.query_count += 1
        self.query_timestamps.append(timestamp)
        self.devices.add(device_ip)
        self.last_seen = timestamp

    def add_request(self, device_ip: str):
        """Record an HTTP request to this domain"""
        self.request_count += 1
        self.devices.add(device_ip)
        self.last_seen = time.time()

    def add_resolved_ip(self, ip: str):
        """Add a resolved IP for this domain"""
        self.resolved_ips.add(ip)

    def get_base_domain(self) -> str:
        """Extract the base domain (e.g., example.com from sub.example.com)"""
        parts = self.domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return self.domain

    def get_query_frequency(self) -> float:
        """Calculate average time between queries in seconds"""
        if len(self.query_timestamps) < 2:
            return 0.0

        timestamps = sorted(self.query_timestamps)
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

        if intervals:
            return sum(intervals) / len(intervals)
        return 0.0

    def is_contacted_recently(self, window: float = 300) -> bool:
        """Check if domain was contacted in the last 'window' seconds"""
        return (time.time() - self.last_seen) < window


class DomainTracker:
    """Tracks activity for all domains"""

    def __init__(self):
        self.domains: Dict[str, DomainProfile] = {}
        self.third_party_domains: Set[str] = set()

        # Common tracking/ad domains (simplified list)
        self.known_trackers = {
            'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
            'facebook.com', 'facebook.net', 'fbcdn.net',
            'googlesyndication.com', 'adservice.google.com',
            'scorecardresearch.com', 'quantserve.com',
            'krxd.net', 'adsafeprotected.com',
        }

    def get_or_create_domain(self, domain: str) -> DomainProfile:
        """Get or create a domain profile"""
        if domain not in self.domains:
            self.domains[domain] = DomainProfile(domain)
        return self.domains[domain]

    def track_dns_query(self, domain: str, device_ip: str, timestamp: float = None):
        """Track a DNS query"""
        profile = self.get_or_create_domain(domain)
        profile.add_query(device_ip, timestamp)

    def track_dns_response(self, domain: str, ips: List[str]):
        """Track a DNS response with resolved IPs"""
        profile = self.get_or_create_domain(domain)
        for ip in ips:
            profile.add_resolved_ip(ip)

    def track_http_request(self, domain: str, device_ip: str):
        """Track an HTTP request to a domain"""
        profile = self.get_or_create_domain(domain)
        profile.add_request(device_ip)

    def mark_third_party(self, domain: str, parent_domain: str):
        """Mark a domain as third-party (loaded from another domain)"""
        profile = self.get_or_create_domain(domain)
        profile.is_third_party = True
        profile.parent_domain = parent_domain
        self.third_party_domains.add(domain)

    def is_known_tracker(self, domain: str) -> bool:
        """Check if domain is a known tracker"""
        base_domain = self.get_or_create_domain(domain).get_base_domain()
        for tracker in self.known_trackers:
            if tracker in domain or tracker in base_domain:
                return True
        return False

    def get_tracking_domains(self) -> List[DomainProfile]:
        """Get all domains that are known trackers"""
        return [
            profile for profile in self.domains.values()
            if self.is_known_tracker(profile.domain)
        ]

    def get_most_queried_domains(self, limit: int = 10) -> List[DomainProfile]:
        """Get the most frequently queried domains"""
        sorted_domains = sorted(
            self.domains.values(),
            key=lambda d: d.query_count,
            reverse=True
        )
        return sorted_domains[:limit]

    def get_domains_for_device(self, device_ip: str) -> List[DomainProfile]:
        """Get all domains contacted by a specific device"""
        return [
            profile for profile in self.domains.values()
            if device_ip in profile.devices
        ]

    def get_third_party_count_for_domain(self, domain: str) -> int:
        """Count third-party domains loaded from a specific domain"""
        count = 0
        for profile in self.domains.values():
            if profile.is_third_party and profile.parent_domain == domain:
                count += 1
        return count

    def get_periodic_domains(self, regularity_threshold: float = 5.0) -> List[tuple]:
        """
        Get domains that are contacted periodically (beaconing behavior)
        Returns list of (domain, average_interval) tuples
        """
        periodic = []

        for profile in self.domains.values():
            if len(profile.query_timestamps) < 5:  # Need at least 5 queries
                continue

            freq = profile.get_query_frequency()
            if freq == 0:
                continue

            timestamps = sorted(profile.query_timestamps)
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]

            if not intervals:
                continue

            # Calculate standard deviation
            avg = sum(intervals) / len(intervals)
            variance = sum((x - avg) ** 2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5

            # If standard deviation is low relative to average, it's periodic
            if avg > 0 and (std_dev / avg) < 0.3:  # Coefficient of variation < 0.3
                periodic.append((profile.domain, avg, len(profile.query_timestamps)))

        return sorted(periodic, key=lambda x: x[1])  # Sort by interval

    def get_domain_summary(self, domain: str) -> dict:
        """Get summary information for a domain"""
        profile = self.domains.get(domain)
        if not profile:
            return None

        return {
            "domain": profile.domain,
            "first_seen": profile.first_seen,
            "last_seen": profile.last_seen,
            "query_count": profile.query_count,
            "request_count": profile.request_count,
            "devices_count": len(profile.devices),
            "resolved_ips": list(profile.resolved_ips),
            "is_third_party": profile.is_third_party,
            "is_tracker": self.is_known_tracker(domain),
            "avg_query_interval": profile.get_query_frequency()
        }
