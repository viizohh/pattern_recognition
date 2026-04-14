"""Beaconing detection - identifies periodic communication patterns

Beaconing is when malware or spyware regularly "phones home" to a command-and-control
(C2) server at consistent intervals (e.g., every 60 seconds). This detector identifies
domains that are contacted with suspicious regularity.
"""

import time
from typing import List, Tuple
from net_watch.tracking.domain_tracker import DomainTracker
from net_watch.alerts import AlertManager
from net_watch.utils import format_duration


class BeaconingDetector:
    """Detects periodic beaconing behavior that may indicate C2 communication

    Beaconing detection works by analyzing DNS query patterns:
    1. Tracks timestamps of all DNS queries for each domain
    2. Calculates the intervals between queries
    3. Uses statistical analysis (coefficient of variation) to identify regular patterns
    4. Alerts when a domain is contacted at suspiciously regular intervals
    """

    def __init__(
        self,
        domain_tracker: DomainTracker,
        alert_manager: AlertManager
    ):
        self.domain_tracker = domain_tracker
        self.alert_manager = alert_manager
        self.detected_beacons = set()  # Track which domains we've already alerted on
        self.last_check = time.time()

        # Detection thresholds
        self.min_queries = 5                # Need at least 5 queries to identify a pattern
        self.regularity_threshold = 0.3     # Coefficient of variation < 0.3 = very regular
        self.check_interval = 60            # Check for beaconing every 60 seconds

    def check_for_beaconing(self):
        """Check for beaconing behavior across all domains

        Analyzes all tracked domains to find those with suspiciously regular
        communication patterns that might indicate malware beaconing.
        """
        current_time = time.time()

        # Don't check too frequently (performance optimization)
        if current_time - self.last_check < self.check_interval:
            return

        self.last_check = current_time

        # Get domains with periodic query patterns from domain tracker
        periodic_domains = self.domain_tracker.get_periodic_domains()

        for domain, interval, query_count in periodic_domains:
            # Skip if we've already alerted about this domain
            if domain in self.detected_beacons:
                continue

            # Get devices that contacted this domain
            profile = self.domain_tracker.get_or_create_domain(domain)
            devices = list(profile.devices)

            # Calculate how long the beaconing has been happening
            if profile.query_timestamps:
                duration = profile.query_timestamps[-1] - profile.query_timestamps[0]
            else:
                continue

            # Generate alert for this beaconing domain
            self._generate_beacon_alert(
                domain,
                devices,
                interval,
                query_count,
                duration
            )

            # Remember that we've alerted about this domain
            self.detected_beacons.add(domain)

    def _generate_beacon_alert(
        self,
        domain: str,
        devices: List[str],
        interval: float,
        query_count: int,
        duration: float
    ):
        """Generate an alert for detected beaconing"""
        device_str = devices[0] if len(devices) == 1 else f"{len(devices)} devices"

        # Format the interval nicely
        if interval < 60:
            interval_str = f"{int(interval)} seconds"
        elif interval < 3600:
            interval_str = f"{int(interval/60)} minutes"
        else:
            interval_str = f"{int(interval/3600)} hours"

        duration_str = format_duration(duration)

        # Check if it's a known tracker (lower severity)
        if self.domain_tracker.is_known_tracker(domain):
            self.alert_manager.info(
                f"{device_str} contacted {domain} every {interval_str} for {duration_str}.",
                explanation="Regular tracking service, likely analytics or ads. Low risk."
            )
        else:
            # Unknown periodic beaconing is more suspicious
            self.alert_manager.alert(
                f"{device_str} contacted {domain} every {interval_str} for {duration_str}.",
                explanation="Behavior matches automated beaconing patterns. Could be legitimate service or malware C2.",
                technical_details=f"Query count: {query_count}, Interval: {interval:.1f}s, Duration: {duration:.1f}s"
            )

    def check_connection_beaconing(self, connections: List) -> List[Tuple]:
        """
        Check for beaconing in TCP connections
        Returns list of (src_ip, dst_ip, interval, count) tuples
        """
        # Group connections by source-destination pair
        from collections import defaultdict
        connection_times = defaultdict(list)

        for conn in connections:
            key = (conn.src_ip, conn.dst_ip)
            connection_times[key].append(conn.start_time)

        beacons = []

        for (src_ip, dst_ip), timestamps in connection_times.items():
            if len(timestamps) < self.min_queries:
                continue

            # Calculate intervals
            sorted_times = sorted(timestamps)
            intervals = [
                sorted_times[i+1] - sorted_times[i]
                for i in range(len(sorted_times) - 1)
            ]

            if not intervals:
                continue

            # Check regularity
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5

            coefficient_of_variation = std_dev / avg_interval if avg_interval > 0 else 1

            if coefficient_of_variation < self.regularity_threshold:
                beacons.append((src_ip, dst_ip, avg_interval, len(timestamps)))

        return beacons

    def analyze_beaconing_pattern(self, timestamps: List[float]) -> dict:
        """
        Analyze a list of timestamps for beaconing characteristics
        Returns analysis results
        """
        if len(timestamps) < 2:
            return {"is_periodic": False}

        sorted_times = sorted(timestamps)
        intervals = [sorted_times[i+1] - sorted_times[i] for i in range(len(sorted_times) - 1)]

        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5
        coefficient_of_variation = std_dev / avg_interval if avg_interval > 0 else 1

        return {
            "is_periodic": coefficient_of_variation < self.regularity_threshold,
            "avg_interval": avg_interval,
            "std_dev": std_dev,
            "coefficient_of_variation": coefficient_of_variation,
            "sample_count": len(timestamps),
            "total_duration": sorted_times[-1] - sorted_times[0]
        }
