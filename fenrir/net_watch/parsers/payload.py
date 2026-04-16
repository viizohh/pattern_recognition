"""Payload parser for extracting sensitive information from packet data.

This module searches packet payloads for potentially sensitive information like:
- Email addresses
- Passwords (in cleartext HTTP/FTP traffic)
- Credit card numbers
- Social security numbers
- API keys and tokens
- Usernames
- Phone numbers
"""

import re
from typing import Dict, List, Optional, Set
from collections import defaultdict


class SensitiveDataFinding:
    """Represents a finding of sensitive data in a packet."""

    def __init__(self, data_type: str, value: str, context: str, source_ip: str, dest_ip: str, protocol: str):
        self.data_type = data_type  # email, password, credit_card, etc.
        self.value = value  # The actual sensitive data found
        self.context = context  # Surrounding text for context
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.protocol = protocol
        self.timestamp = None


class PayloadParser:
    """Parses packet payloads to extract sensitive information."""

    def __init__(self):
        # Patterns for detecting sensitive data
        self.patterns = {
            'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
            'credit_card': re.compile(r'\b(?:\d{4}[-\s]?){3}\d{4}\b'),
            'ssn': re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
            'phone': re.compile(r'\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'),
            'api_key': re.compile(r'\b(?:api[_-]?key|apikey|access[_-]?token)["\s:=]+([A-Za-z0-9_\-]{20,})', re.IGNORECASE),
            'bearer_token': re.compile(r'Bearer\s+([A-Za-z0-9_\-\.=]+)', re.IGNORECASE),
            'jwt': re.compile(r'\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
        }

        # Password field patterns (HTTP POST data)
        self.password_patterns = [
            re.compile(r'password["\s:=]+([^\s&"]+)', re.IGNORECASE),
            re.compile(r'passwd["\s:=]+([^\s&"]+)', re.IGNORECASE),
            re.compile(r'pwd["\s:=]+([^\s&"]+)', re.IGNORECASE),
            re.compile(r'pass["\s:=]+([^\s&"]+)', re.IGNORECASE),
        ]

        # Username patterns
        self.username_patterns = [
            re.compile(r'username["\s:=]+([^\s&"]+)', re.IGNORECASE),
            re.compile(r'user["\s:=]+([^\s&"]+)', re.IGNORECASE),
            re.compile(r'email["\s:=]+([^\s&"]+)', re.IGNORECASE),
            re.compile(r'login["\s:=]+([^\s&"]+)', re.IGNORECASE),
        ]

        # Findings storage
        self.findings: List[SensitiveDataFinding] = []
        self.findings_by_type: Dict[str, List[SensitiveDataFinding]] = defaultdict(list)

        self.seen_values: Set[str] = set()

    def parse_packet(self, packet) -> Optional[List[SensitiveDataFinding]]:
        """
        Parse a packet for sensitive data.

        Returns a list of findings if any sensitive data is detected.
        """
        try:
            from scapy.all import IP, TCP, UDP, Raw

            if not packet.haslayer(Raw):
                return None

            src_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
            dst_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"

            if packet.haslayer(TCP):
                protocol = f"TCP:{packet[TCP].dport}"
            elif packet.haslayer(UDP):
                protocol = f"UDP:{packet[UDP].dport}"
            else:
                protocol = "unknown"

            payload = packet[Raw].load

            # Try to decode as text
            try:
                payload_text = payload.decode('utf-8', errors='ignore')
            except:
                payload_text = payload.decode('latin-1', errors='ignore')

            # Only process if payload contains printable text
            if not any(c.isprintable() for c in payload_text):
                return None

            findings = []

            # Search for emails
            for match in self.patterns['email'].finditer(payload_text):
                email = match.group(0)
                if email not in self.seen_values:
                    context = self._get_context(payload_text, match.start(), match.end())
                    finding = SensitiveDataFinding(
                        data_type="email",
                        value=email,
                        context=context,
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        protocol=protocol
                    )
                    findings.append(finding)
                    self.seen_values.add(email)
                    self.findings_by_type["email"].append(finding)

            # Search for passwords
            for pattern in self.password_patterns:
                for match in pattern.finditer(payload_text):
                    password = match.group(1) if match.groups() else match.group(0)
                    # Filter out common false positives
                    if len(password) > 3 and password not in ['null', 'undefined', '']:
                        key = f"password:{password}"
                        if key not in self.seen_values:
                            context = self._get_context(payload_text, match.start(), match.end())
                            finding = SensitiveDataFinding(
                                data_type="password",
                                value=password,
                                context=context,
                                source_ip=src_ip,
                                dest_ip=dst_ip,
                                protocol=protocol
                            )
                            findings.append(finding)
                            self.seen_values.add(key)
                            self.findings_by_type["password"].append(finding)

            # Search for usernames
            for pattern in self.username_patterns:
                for match in pattern.finditer(payload_text):
                    username = match.group(1) if match.groups() else match.group(0)
                    if len(username) > 2:
                        key = f"username:{username}"
                        if key not in self.seen_values:
                            context = self._get_context(payload_text, match.start(), match.end())
                            finding = SensitiveDataFinding(
                                data_type="username",
                                value=username,
                                context=context,
                                source_ip=src_ip,
                                dest_ip=dst_ip,
                                protocol=protocol
                            )
                            findings.append(finding)
                            self.seen_values.add(key)
                            self.findings_by_type["username"].append(finding)

            # Search for credit cards
            for match in self.patterns['credit_card'].finditer(payload_text):
                cc_number = match.group(0).replace('-', '').replace(' ', '')
                if self._is_valid_luhn(cc_number):
                    if cc_number not in self.seen_values:
                        context = self._get_context(payload_text, match.start(), match.end())
                        finding = SensitiveDataFinding(
                            data_type="credit_card",
                            value=self._mask_sensitive_data(cc_number, 'credit_card'),
                            context=context,
                            source_ip=src_ip,
                            dest_ip=dst_ip,
                            protocol=protocol
                        )
                        findings.append(finding)
                        self.seen_values.add(cc_number)
                        self.findings_by_type["credit_card"].append(finding)

            # Search for SSN
            for match in self.patterns['ssn'].finditer(payload_text):
                ssn = match.group(0)
                if ssn not in self.seen_values:
                    context = self._get_context(payload_text, match.start(), match.end())
                    finding = SensitiveDataFinding(
                        data_type="ssn",
                        value=self._mask_sensitive_data(ssn, 'ssn'),
                        context=context,
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        protocol=protocol
                    )
                    findings.append(finding)
                    self.seen_values.add(ssn)
                    self.findings_by_type["ssn"].append(finding)

            # Search for API keys
            for match in self.patterns['api_key'].finditer(payload_text):
                api_key = match.group(1) if match.groups() else match.group(0)
                if api_key not in self.seen_values:
                    context = self._get_context(payload_text, match.start(), match.end())
                    finding = SensitiveDataFinding(
                        data_type="api_key",
                        value=self._mask_sensitive_data(api_key, 'api_key'),
                        context=context,
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        protocol=protocol
                    )
                    findings.append(finding)
                    self.seen_values.add(api_key)
                    self.findings_by_type["api_key"].append(finding)

            # Search for Bearer tokens
            for match in self.patterns['bearer_token'].finditer(payload_text):
                token = match.group(1)
                if token not in self.seen_values:
                    context = self._get_context(payload_text, match.start(), match.end())
                    finding = SensitiveDataFinding(
                        data_type="bearer_token",
                        value=self._mask_sensitive_data(token, 'token'),
                        context=context,
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        protocol=protocol
                    )
                    findings.append(finding)
                    self.seen_values.add(token)
                    self.findings_by_type["bearer_token"].append(finding)

            # Search for JWTs
            for match in self.patterns['jwt'].finditer(payload_text):
                jwt = match.group(0)
                if jwt not in self.seen_values:
                    context = self._get_context(payload_text, match.start(), match.end())
                    finding = SensitiveDataFinding(
                        data_type="jwt",
                        value=self._mask_sensitive_data(jwt, 'jwt'),
                        context=context,
                        source_ip=src_ip,
                        dest_ip=dst_ip,
                        protocol=protocol
                    )
                    findings.append(finding)
                    self.seen_values.add(jwt)
                    self.findings_by_type["jwt"].append(finding)

            if findings:
                self.findings.extend(findings)
                return findings

            return None

        except Exception as e:
            # Silently ignore parsing errors
            return None

    def _get_context(self, text: str, start: int, end: int, context_chars: int = 40) -> str:
        """Get context around a match for display."""
        context_start = max(0, start - context_chars)
        context_end = min(len(text), end + context_chars)
        context = text[context_start:context_end]

        # Clean up the context
        context = ' '.join(context.split())  # Normalize whitespace
        return context[:100]  # Limit to 100 chars

    def _mask_sensitive_data(self, value: str, data_type: str) -> str:
        """Mask sensitive data for display."""
        if data_type == 'credit_card':
            return f"****-****-****-{value[-4:]}"
        elif data_type == 'ssn':
            return f"***-**-{value[-4:]}"
        elif data_type in ['api_key', 'token', 'jwt']:
            if len(value) > 8:
                return f"{value[:4]}...{value[-4:]}"
            return "****"
        return value

    def _is_valid_luhn(self, card_number: str) -> bool:
        """Validate credit card using Luhn algorithm."""
        try:
            digits = [int(d) for d in card_number if d.isdigit()]
            checksum = 0
            is_second = False

            for i in range(len(digits) - 1, -1, -1):
                d = digits[i]
                if is_second:
                    d = d * 2
                    if d > 9:
                        d = d - 9
                checksum += d
                is_second = not is_second

            return (checksum % 10) == 0
        except:
            return False

    def get_summary(self) -> Dict[str, int]:
        """Get summary of findings by type."""
        return {
            data_type: len(findings)
            for data_type, findings in self.findings_by_type.items()
        }

    def get_findings_by_type(self, data_type: str) -> List[SensitiveDataFinding]:
        """Get all findings of a specific type."""
        return self.findings_by_type.get(data_type, [])
