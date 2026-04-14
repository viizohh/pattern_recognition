"""Connection tracking and analysis"""

import time
from typing import Dict, List, Tuple
from collections import defaultdict


class ConnectionStats:
    """Statistics for connections"""

    def __init__(self):
        self.total_connections = 0
        self.active_connections = 0
        self.failed_connections = 0
        self.connection_start_times: List[float] = []
        self.connection_durations: List[float] = []
        self.ports_accessed: Dict[int, int] = defaultdict(int)
        self.connection_pairs: Dict[Tuple[str, str], int] = defaultdict(int)  # (src, dst) -> count

    def add_connection(self, src_ip: str, dst_ip: str, dst_port: int, timestamp: float = None):
        """Record a new connection"""
        if timestamp is None:
            timestamp = time.time()

        self.total_connections += 1
        self.active_connections += 1
        self.connection_start_times.append(timestamp)
        self.ports_accessed[dst_port] += 1
        self.connection_pairs[(src_ip, dst_ip)] += 1

    def add_failed_connection(self, src_ip: str, dst_ip: str, dst_port: int):
        """Record a failed connection attempt"""
        self.failed_connections += 1
        self.ports_accessed[dst_port] += 1

    def close_connection(self, duration: float):
        """Mark a connection as closed"""
        if self.active_connections > 0:
            self.active_connections -= 1
        self.connection_durations.append(duration)

    def get_average_duration(self) -> float:
        """Get average connection duration"""
        if not self.connection_durations:
            return 0.0
        return sum(self.connection_durations) / len(self.connection_durations)

    def get_most_common_ports(self, limit: int = 5) -> List[Tuple[int, int]]:
        """Get most commonly accessed ports"""
        sorted_ports = sorted(
            self.ports_accessed.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_ports[:limit]

    def get_connection_rate(self, window: float = 60.0) -> float:
        """Calculate connections per second in recent window"""
        current_time = time.time()
        recent_connections = [
            ts for ts in self.connection_start_times
            if current_time - ts <= window
        ]

        if not recent_connections:
            return 0.0

        return len(recent_connections) / window


class ConnectionTracker:
    """Tracks all network connections"""

    def __init__(self):
        self.stats = ConnectionStats()
        self.device_connections: Dict[str, ConnectionStats] = defaultdict(ConnectionStats)
        self.port_stats: Dict[int, Dict] = defaultdict(lambda: {
            'connections': 0,
            'failures': 0,
            'unique_sources': set(),
            'unique_destinations': set()
        })

    def track_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        success: bool = True,
        timestamp: float = None
    ):
        """Track a connection attempt"""
        if success:
            self.stats.add_connection(src_ip, dst_ip, dst_port, timestamp)
            self.device_connections[src_ip].add_connection(src_ip, dst_ip, dst_port, timestamp)

            # Update port stats
            self.port_stats[dst_port]['connections'] += 1
            self.port_stats[dst_port]['unique_sources'].add(src_ip)
            self.port_stats[dst_port]['unique_destinations'].add(dst_ip)
        else:
            self.stats.add_failed_connection(src_ip, dst_ip, dst_port)
            self.device_connections[src_ip].add_failed_connection(src_ip, dst_ip, dst_port)
            self.port_stats[dst_port]['failures'] += 1

    def close_connection(self, src_ip: str, duration: float):
        """Record a connection closure"""
        self.stats.close_connection(duration)
        self.device_connections[src_ip].close_connection(duration)

    def get_devices_with_high_failure_rate(self, threshold: float = 0.3) -> List[str]:
        """Get devices with high connection failure rate"""
        devices = []

        for ip, stats in self.device_connections.items():
            total = stats.total_connections + stats.failed_connections
            if total < 10:  # Need minimum attempts
                continue

            failure_rate = stats.failed_connections / total
            if failure_rate > threshold:
                devices.append((ip, failure_rate, stats.failed_connections))

        return sorted(devices, key=lambda x: x[1], reverse=True)

    def get_suspicious_ports(self) -> List[Tuple[int, dict]]:
        """
        Get ports with suspicious activity
        (high failure rate or unusual patterns)
        """
        suspicious = []

        for port, stats in self.port_stats.items():
            total_attempts = stats['connections'] + stats['failures']
            if total_attempts < 5:
                continue

            # High failure rate
            failure_rate = stats['failures'] / total_attempts if total_attempts > 0 else 0

            # Unusual ports (not in common list)
            common_ports = {80, 443, 53, 22, 21, 25, 110, 143, 993, 995, 3389, 8080}
            is_uncommon = port not in common_ports

            # Many sources to same destination (potential scanning)
            source_to_dest_ratio = len(stats['unique_sources']) / max(len(stats['unique_destinations']), 1)

            if failure_rate > 0.5 or (is_uncommon and total_attempts > 10) or source_to_dest_ratio > 5:
                suspicious.append((port, {
                    'total_attempts': total_attempts,
                    'failures': stats['failures'],
                    'failure_rate': failure_rate,
                    'unique_sources': len(stats['unique_sources']),
                    'unique_destinations': len(stats['unique_destinations']),
                    'is_uncommon': is_uncommon
                }))

        return sorted(suspicious, key=lambda x: x[1]['total_attempts'], reverse=True)

    def get_burst_connections(self, window: float = 10.0, threshold: int = 50) -> List[Tuple[str, float]]:
        """Detect connection bursts (many connections in short time)"""
        bursts = []
        current_time = time.time()

        for ip, stats in self.device_connections.items():
            recent = [
                ts for ts in stats.connection_start_times
                if current_time - ts <= window
            ]

            if len(recent) >= threshold:
                rate = len(recent) / window
                bursts.append((ip, rate))

        return sorted(bursts, key=lambda x: x[1], reverse=True)

    def get_connection_summary(self) -> dict:
        """Get overall connection summary"""
        return {
            'total_connections': self.stats.total_connections,
            'active_connections': self.stats.active_connections,
            'failed_connections': self.stats.failed_connections,
            'avg_duration': self.stats.get_average_duration(),
            'unique_devices': len(self.device_connections),
            'unique_ports': len(self.port_stats),
            'connection_rate': self.stats.get_connection_rate()
        }

    def get_device_connection_summary(self, device_ip: str) -> dict:
        """Get connection summary for a specific device"""
        stats = self.device_connections.get(device_ip)
        if not stats:
            return None

        return {
            'total_connections': stats.total_connections,
            'active_connections': stats.active_connections,
            'failed_connections': stats.failed_connections,
            'avg_duration': stats.get_average_duration(),
            'most_common_ports': stats.get_most_common_ports(),
            'connection_rate': stats.get_connection_rate()
        }
