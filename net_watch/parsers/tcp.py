"""TCP connection parser and tracker"""

import time
from typing import Dict, Tuple, Optional
from scapy.all import TCP, IP


class TCPConnection:
    """Represents a TCP connection"""

    def __init__(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.start_time = time.time()
        self.last_seen = self.start_time
        self.packets = 0
        self.bytes_sent = 0
        self.established = False
        self.closed = False
        self.idle_periods = []

    def update(self, packet_size: int, flags: int):
        """Update connection state"""
        current_time = time.time()

        # Track idle time
        idle_time = current_time - self.last_seen
        if idle_time > 60:  # More than 1 minute idle
            self.idle_periods.append(idle_time)

        self.last_seen = current_time
        self.packets += 1
        self.bytes_sent += packet_size

        # Check flags
        if flags & 0x02:  # SYN flag
            pass
        if flags & 0x10:  # ACK flag
            self.established = True
        if flags & 0x01:  # FIN flag
            self.closed = True
        if flags & 0x04:  # RST flag
            self.closed = True

    def get_duration(self) -> float:
        """Get connection duration in seconds"""
        return self.last_seen - self.start_time

    def is_idle(self, threshold: float = 300) -> bool:
        """Check if connection has been idle for more than threshold seconds"""
        return (time.time() - self.last_seen) > threshold

    def get_connection_key(self) -> str:
        """Get a unique key for this connection"""
        return f"{self.src_ip}:{self.src_port}-{self.dst_ip}:{self.dst_port}"


class TCPParser:
    """Parses and tracks TCP connections"""

    def __init__(self):
        self.connections: Dict[str, TCPConnection] = {}
        self.failed_connections: Dict[Tuple[str, int], int] = {}  # (ip, port) -> count
        self.connection_history = []

    def parse_packet(self, packet):
        """Parse a TCP packet"""
        if not packet.haslayer(TCP) or not packet.haslayer(IP):
            return None

        tcp = packet[TCP]
        ip = packet[IP]
        timestamp = time.time()

        src_ip = ip.src
        dst_ip = ip.dst
        src_port = tcp.sport
        dst_port = tcp.dport
        flags = tcp.flags
        packet_size = len(packet)

        # Create connection key (bidirectional)
        conn_key_fwd = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
        conn_key_rev = f"{dst_ip}:{dst_port}-{src_ip}:{src_port}"

        # Find existing connection
        conn = None
        if conn_key_fwd in self.connections:
            conn = self.connections[conn_key_fwd]
        elif conn_key_rev in self.connections:
            conn = self.connections[conn_key_rev]

        # Check for SYN without ACK (new connection attempt)
        if flags & 0x02 and not (flags & 0x10):  # SYN but not ACK
            if conn is None:
                conn = TCPConnection(src_ip, src_port, dst_ip, dst_port)
                self.connections[conn_key_fwd] = conn

        # Update existing connection
        if conn:
            conn.update(packet_size, flags)

        # Check for RST (failed connection)
        if flags & 0x04:  # RST flag
            key = (dst_ip, dst_port)
            self.failed_connections[key] = self.failed_connections.get(key, 0) + 1

        return {
            "type": "tcp_packet",
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "source_port": src_port,
            "dest_port": dst_port,
            "flags": flags,
            "size": packet_size,
            "timestamp": timestamp
        }

    def get_active_connections(self) -> list:
        """Get all currently active connections"""
        return [conn for conn in self.connections.values() if not conn.closed]

    def get_long_lived_connections(self, min_duration: float = 3600) -> list:
        """Get connections that have been open for a long time"""
        return [
            conn for conn in self.connections.values()
            if conn.get_duration() > min_duration and not conn.closed
        ]

    def get_idle_connections(self, idle_threshold: float = 300) -> list:
        """Get connections that are idle but still open"""
        return [
            conn for conn in self.connections.values()
            if conn.is_idle(idle_threshold) and not conn.closed
        ]

    def get_failed_connection_targets(self) -> list:
        """Get IPs/ports with repeated failed connections"""
        return [
            (ip, port, count)
            for (ip, port), count in self.failed_connections.items()
            if count > 5
        ]

    def cleanup_old_connections(self, age_threshold: float = 7200):
        """Remove old closed connections to save memory"""
        current_time = time.time()
        to_remove = []

        for key, conn in self.connections.items():
            if conn.closed and (current_time - conn.last_seen) > age_threshold:
                to_remove.append(key)

        for key in to_remove:
            del self.connections[key]
