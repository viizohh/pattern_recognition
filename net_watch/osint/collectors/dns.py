"""DNS intelligence collector

Performs DNS lookups to gather:
- A/AAAA records (IP addresses)
- NS records (nameservers)
- SOA record (zone authority)
- MX records (mail servers)
- TXT records (SPF, DMARC, DKIM hints, etc.)
"""

import dns.resolver
import dns.exception
from typing import List, Dict, Optional


class DNSCollector:
    """Collect DNS intelligence for a domain"""

    def __init__(self, timeout: int = 10):
        """Initialize DNS collector

        Args:
            timeout: DNS query timeout in seconds
        """
        self.timeout = timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout

    def collect(self, domain: str) -> Dict:
        """Collect all DNS information for domain

        Args:
            domain: Domain to query

        Returns:
            Dictionary with DNS records
        """
        results = {
            'domain': domain,
            'a_records': self.get_a_records(domain),
            'aaaa_records': self.get_aaaa_records(domain),
            'ns_records': self.get_ns_records(domain),
            'mx_records': self.get_mx_records(domain),
            'txt_records': self.get_txt_records(domain),
            'soa_record': self.get_soa_record(domain),
            'spf': None,
            'dmarc': None,
            'dkim_hints': [],
        }

        # Parse TXT records for security information
        if results['txt_records']:
            results['spf'] = self._extract_spf(results['txt_records'])
            results['dkim_hints'] = self._extract_dkim_hints(results['txt_records'])

        # Check for DMARC record (separate query for _dmarc subdomain)
        results['dmarc'] = self.get_dmarc_record(domain)

        return results

    def get_a_records(self, domain: str) -> List[str]:
        """Get A records (IPv4 addresses)

        Args:
            domain: Domain to query

        Returns:
            List of IPv4 addresses
        """
        try:
            answers = self.resolver.resolve(domain, 'A')
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception:
            return []

    def get_aaaa_records(self, domain: str) -> List[str]:
        """Get AAAA records (IPv6 addresses)

        Args:
            domain: Domain to query

        Returns:
            List of IPv6 addresses
        """
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception:
            return []

    def get_ns_records(self, domain: str) -> List[str]:
        """Get NS records (nameservers)

        Args:
            domain: Domain to query

        Returns:
            List of nameserver hostnames
        """
        try:
            answers = self.resolver.resolve(domain, 'NS')
            return [str(rdata).rstrip('.') for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception:
            return []

    def get_mx_records(self, domain: str) -> List[Dict[str, any]]:
        """Get MX records (mail servers)

        Args:
            domain: Domain to query

        Returns:
            List of dicts with 'priority' and 'host' keys
        """
        try:
            answers = self.resolver.resolve(domain, 'MX')
            return [
                {
                    'priority': rdata.preference,
                    'host': str(rdata.exchange).rstrip('.')
                }
                for rdata in answers
            ]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception:
            return []

    def get_txt_records(self, domain: str) -> List[str]:
        """Get TXT records

        Args:
            domain: Domain to query

        Returns:
            List of TXT record strings
        """
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            # TXT records can be split across multiple strings
            return [
                ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                for rdata in answers
            ]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception:
            return []

    def get_soa_record(self, domain: str) -> Optional[Dict]:
        """Get SOA record (zone authority)

        Args:
            domain: Domain to query

        Returns:
            Dictionary with SOA information or None
        """
        try:
            answers = self.resolver.resolve(domain, 'SOA')
            if answers:
                soa = answers[0]
                return {
                    'mname': str(soa.mname).rstrip('.'),
                    'rname': str(soa.rname).rstrip('.'),
                    'serial': soa.serial,
                    'refresh': soa.refresh,
                    'retry': soa.retry,
                    'expire': soa.expire,
                    'minimum': soa.minimum,
                }
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return None
        except Exception:
            return None

    def get_dmarc_record(self, domain: str) -> Optional[str]:
        """Get DMARC policy record

        DMARC records are TXT records at _dmarc.domain.com

        Args:
            domain: Domain to query

        Returns:
            DMARC policy string or None
        """
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
                if txt.startswith('v=DMARC1'):
                    return txt
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return None
        except Exception:
            return None

    def _extract_spf(self, txt_records: List[str]) -> Optional[str]:
        """Extract SPF record from TXT records

        SPF records start with "v=spf1"

        Args:
            txt_records: List of TXT records

        Returns:
            SPF policy string or None
        """
        for record in txt_records:
            if record.startswith('v=spf1'):
                return record
        return None

    def _extract_dkim_hints(self, txt_records: List[str]) -> List[str]:
        """Extract DKIM selector hints from TXT records

        DKIM records start with "v=DKIM1"

        Args:
            txt_records: List of TXT records

        Returns:
            List of DKIM hints found
        """
        hints = []
        for record in txt_records:
            if 'dkim' in record.lower():
                hints.append(record)
        return hints

    def has_mx_records(self, domain: str) -> bool:
        """Check if domain has MX records (can receive email)

        Args:
            domain: Domain to check

        Returns:
            True if MX records exist
        """
        mx_records = self.get_mx_records(domain)
        return len(mx_records) > 0
