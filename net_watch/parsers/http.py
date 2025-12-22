"""HTTP/HTTPS traffic parser"""

import time
from typing import Dict, Optional, Set
from scapy.all import TCP, IP, Raw


class HTTPParser:
    """Parses HTTP traffic (note: HTTPS is encrypted, only metadata available)"""

    def __init__(self):
        self.http_requests: Dict[str, list] = {}  # host -> [requests]
        self.http_responses: Dict[str, list] = {}  # host -> [responses]
        self.user_agents: Dict[str, Set] = {}  # ip -> {user agents}

    def parse_packet(self, packet):
        """Parse HTTP traffic"""
        if not packet.haslayer(TCP):
            return None

        tcp = packet[TCP]
        timestamp = time.time()

        # HTTP typically uses port 80
        if tcp.dport == 80 or tcp.sport == 80:
            if packet.haslayer(Raw):
                payload = packet[Raw].load

                try:
                    payload_str = payload.decode('utf-8', errors='ignore')

                    # Check for HTTP request
                    if payload_str.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ')):
                        return self._handle_http_request(payload_str, packet, timestamp)

                    # Check for HTTP response
                    elif payload_str.startswith('HTTP/'):
                        return self._handle_http_response(payload_str, packet, timestamp)

                except Exception:
                    pass

        # HTTPS detection (port 443) - we can only see metadata
        if tcp.dport == 443 or tcp.sport == 443:
            return self._handle_https_connection(packet, timestamp)

        return None

    def _handle_http_request(self, payload: str, packet, timestamp: float) -> dict:
        """Handle HTTP request"""
        lines = payload.split('\r\n')
        if not lines:
            return None

        # Parse request line
        request_line = lines[0]
        parts = request_line.split(' ')
        if len(parts) < 3:
            return None

        method = parts[0]
        path = parts[1]

        # Extract Host header
        host = None
        user_agent = None
        for line in lines[1:]:
            if line.lower().startswith('host:'):
                host = line.split(':', 1)[1].strip()
            elif line.lower().startswith('user-agent:'):
                user_agent = line.split(':', 1)[1].strip()

        if host:
            if host not in self.http_requests:
                self.http_requests[host] = []
            self.http_requests[host].append({
                'method': method,
                'path': path,
                'timestamp': timestamp
            })

        src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"

        return {
            "type": "http_request",
            "method": method,
            "host": host,
            "path": path,
            "source_ip": src_ip,
            "user_agent": user_agent,
            "timestamp": timestamp
        }

    def _handle_http_response(self, payload: str, packet, timestamp: float) -> dict:
        """Handle HTTP response"""
        lines = payload.split('\r\n')
        if not lines:
            return None

        # Parse status line
        status_line = lines[0]
        parts = status_line.split(' ', 2)
        if len(parts) < 3:
            return None

        status_code = parts[1]

        return {
            "type": "http_response",
            "status_code": status_code,
            "timestamp": timestamp
        }

    def _handle_https_connection(self, packet, timestamp: float) -> dict:
        """Handle HTTPS connection (metadata only)"""
        src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
        dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"
        tcp = packet[TCP]

        return {
            "type": "https_connection",
            "source_ip": src_ip,
            "dest_ip": dst_ip,
            "source_port": tcp.sport,
            "dest_port": tcp.dport,
            "flags": tcp.flags,
            "timestamp": timestamp
        }

    def get_requests_for_host(self, host: str) -> list:
        """Get all HTTP requests for a specific host"""
        return self.http_requests.get(host, [])

    def get_unique_hosts(self) -> set:
        """Get all unique hosts contacted"""
        return set(self.http_requests.keys())
