"""Certificate Transparency (CT) log collector

Queries public CT logs to discover subdomains passively.

When websites get SSL certificates, they're logged publicly. By searching
these logs, we can discover subdomains like:
- mail.example.com
- vpn.example.com
- dev.example.com
- staging.example.com

Uses crt.sh (free, no API key required).
"""

import requests
from typing import List, Set
from urllib.parse import quote


class CTCollector:
    """Collect subdomain information from Certificate Transparency logs"""

    def __init__(self, timeout: int = 15):
        """Initialize CT collector

        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Hound-OSINT/1.0 (Educational Security Research)'
        })

        # crt.sh is a free CT log search service
        self.crtsh_url = "https://crt.sh/"

    def collect_subdomains(self, domain: str) -> Set[str]:
        """Collect subdomains from Certificate Transparency logs

        Args:
            domain: Domain to search for

        Returns:
            Set of unique subdomains found in CT logs
        """
        subdomains = set()

        try:
            # Query crt.sh for the domain
            # The % wildcard will find *.domain.com
            search_domain = f"%.{domain}"
            params = {
                'q': search_domain,
                'output': 'json'
            }

            response = self.session.get(
                self.crtsh_url,
                params=params,
                timeout=self.timeout
            )

            if response.status_code == 200:
                try:
                    certificates = response.json()

                    # Extract unique domain names from certificates
                    for cert in certificates:
                        # Certificates can cover multiple domains (SANs - Subject Alternative Names)
                        if 'name_value' in cert:
                            names = cert['name_value'].split('\n')
                            for name in names:
                                name = name.strip().lower()

                                # Filter to only include subdomains of target domain
                                if name.endswith(domain):
                                    # Exclude wildcards (e.g., *.example.com)
                                    if not name.startswith('*'):
                                        subdomains.add(name)

                except ValueError:
                    # Response wasn't JSON
                    pass

        except requests.exceptions.Timeout:
            # CT query timed out, return what we have
            pass
        except requests.exceptions.RequestException:
            # Network error, return what we have
            pass
        except Exception:
            # Other error, return what we have
            pass

        return subdomains

    def collect_with_metadata(self, domain: str) -> List[dict]:
        """Collect subdomains with certificate metadata

        Args:
            domain: Domain to search for

        Returns:
            List of dictionaries with subdomain and certificate info
        """
        results = []
        seen_domains = set()

        try:
            search_domain = f"%.{domain}"
            params = {
                'q': search_domain,
                'output': 'json'
            }

            response = self.session.get(
                self.crtsh_url,
                params=params,
                timeout=self.timeout
            )

            if response.status_code == 200:
                try:
                    certificates = response.json()

                    for cert in certificates:
                        if 'name_value' in cert:
                            names = cert['name_value'].split('\n')
                            for name in names:
                                name = name.strip().lower()

                                # Only include subdomains of target, no wildcards
                                if name.endswith(domain) and not name.startswith('*'):
                                    # Avoid duplicates
                                    if name not in seen_domains:
                                        seen_domains.add(name)

                                        results.append({
                                            'subdomain': name,
                                            'issuer': cert.get('issuer_name', 'Unknown'),
                                            'not_before': cert.get('not_before', None),
                                            'not_after': cert.get('not_after', None),
                                        })

                except ValueError:
                    pass

        except requests.exceptions.Timeout:
            pass
        except requests.exceptions.RequestException:
            pass
        except Exception:
            pass

        return results

    def count_subdomains(self, domain: str) -> int:
        """Count how many subdomains were found

        Args:
            domain: Domain to search

        Returns:
            Number of unique subdomains found
        """
        subdomains = self.collect_subdomains(domain)
        return len(subdomains)

    def filter_interesting_subdomains(self, subdomains: Set[str]) -> dict:
        """Categorize subdomains by type

        Args:
            subdomains: Set of subdomains

        Returns:
            Dictionary categorizing subdomains by purpose
        """
        categories = {
            'mail': [],
            'dev': [],
            'staging': [],
            'vpn': [],
            'admin': [],
            'api': [],
            'other': []
        }

        keywords = {
            'mail': ['mail', 'smtp', 'imap', 'pop', 'webmail', 'email'],
            'dev': ['dev', 'development', 'test', 'testing'],
            'staging': ['staging', 'stage', 'stg', 'uat'],
            'vpn': ['vpn', 'remote', 'access'],
            'admin': ['admin', 'administrator', 'manage', 'panel'],
            'api': ['api', 'rest', 'graphql', 'gateway'],
        }

        for subdomain in subdomains:
            categorized = False

            for category, kw_list in keywords.items():
                if any(kw in subdomain.lower() for kw in kw_list):
                    categories[category].append(subdomain)
                    categorized = True
                    break

            if not categorized:
                categories['other'].append(subdomain)

        return categories
