"""DNS traffic parser"""

import time
from typing import Dict, Set
from scapy.all import DNS, DNSQR, DNSRR, IP
from net_watch.utils import calculate_entropy


class DNSParser:
    """Parses and tracks DNS queries and responses"""

    def __init__(self):
        self.queries: Dict[str, list] = {}  # domain -> [timestamps]
        self.responses: Dict[str, Set[str]] = {}  # domain -> {ips}
        self.reverse_lookups: Dict[str, str] = {}  # ip -> domain
        self.failed_queries: Dict[str, int] = {}  # domain -> count

    def parse_packet(self, packet):
        """Parse a DNS packet"""
        if not packet.haslayer(DNS):
            return None

        dns = packet[DNS]
        timestamp = time.time()

        # Query
        if dns.qr == 0 and dns.qd:
            query_name = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')
            return self._handle_query(query_name, timestamp, packet)

        # Response
        elif dns.qr == 1:
            return self._handle_response(dns, timestamp, packet)

        return None

    def _handle_query(self, query_name: str, timestamp: float, packet) -> dict:
        """Handle a DNS query"""
        if query_name not in self.queries:
            self.queries[query_name] = []
        self.queries[query_name].append(timestamp)

        # Calculate entropy (high entropy might indicate DGA domains)
        entropy = calculate_entropy(query_name)

        src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"

        return {
            "type": "dns_query",
            "domain": query_name,
            "source_ip": src_ip,
            "timestamp": timestamp,
            "entropy": entropy
        }

    def _handle_response(self, dns, timestamp: float, packet) -> dict:
        """Handle a DNS response"""
        if not dns.an:
            return None

        query_name = None
        if dns.qd:
            query_name = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.')

        ips = []
        for i in range(dns.ancount):
            answer = dns.an[i]
            if answer.type == 1:  # A record
                ip = answer.rdata
                ips.append(ip)

                if query_name:
                    if query_name not in self.responses:
                        self.responses[query_name] = set()
                    self.responses[query_name].add(ip)

                    self.reverse_lookups[ip] = query_name

        if ips and query_name:
            return {
                "type": "dns_response",
                "domain": query_name,
                "ips": ips,
                "timestamp": timestamp
            }

        return None

    def get_domain_query_count(self, domain: str) -> int:
        """Get the number of queries for a domain"""
        return len(self.queries.get(domain, []))

    def get_domain_for_ip(self, ip: str) -> str:
        """Get the domain name for an IP (from DNS records)"""
        return self.reverse_lookups.get(ip, ip)

    def get_query_timestamps(self, domain: str) -> list:
        """Get all query timestamps for a domain"""
        return self.queries.get(domain, [])

    def get_high_entropy_domains(self, threshold: float = 3.5) -> list:
        """Get domains with high entropy (potential DGA)"""
        high_entropy = []
        for domain in self.queries.keys():
            entropy = calculate_entropy(domain)
            if entropy > threshold:
                high_entropy.append((domain, entropy))
        return sorted(high_entropy, key=lambda x: x[1], reverse=True)
