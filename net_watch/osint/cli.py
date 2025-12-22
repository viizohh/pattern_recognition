"""Main OSINT CLI orchestrator

Coordinates all collectors, parsers, and output formatters.
"""

import time
from typing import Dict, List, Optional
from net_watch.osint.collectors.rdap import RDAPCollector
from net_watch.osint.collectors.dns import DNSCollector
from net_watch.osint.collectors.ct import CTCollector
from net_watch.osint.collectors.web import WebCollector
from net_watch.osint.parsers.emails import EmailParser
from net_watch.osint.output.json_output import JSONFormatter
from net_watch.osint.output.table import TableFormatter
from net_watch.osint.utils import (
    normalize_domain,
    RateLimiter,
    is_valid_email,
    extract_domain_from_email,
    load_keywords_from_file,
    DEFAULT_KEYWORDS,
)


class OSINTOrchestrator:
    """Orchestrate OSINT data collection and output"""

    def __init__(
        self,
        timeout: int = 10,
        max_pages: int = 10,
        delay: float = 1.0,
        polite: bool = False
    ):
        """Initialize OSINT orchestrator

        Args:
            timeout: Request timeout in seconds
            max_pages: Maximum web pages to scrape
            delay: Delay between requests in seconds
            polite: Enable polite mode (slower, more respectful)
        """
        self.timeout = timeout
        self.max_pages = max_pages

        # Set delay based on polite mode
        if polite:
            self.delay = max(delay, 3.0)  # At least 3 seconds in polite mode
        else:
            self.delay = delay

        # Initialize rate limiter
        self.rate_limiter = RateLimiter(delay=self.delay)

        # Initialize collectors
        self.rdap_collector = RDAPCollector(timeout=timeout)
        self.dns_collector = DNSCollector(timeout=timeout)
        self.ct_collector = CTCollector(timeout=timeout)
        self.web_collector = WebCollector(timeout=timeout, max_pages=max_pages)

        # Initialize parsers
        self.email_parser = EmailParser()

        # Initialize formatters
        self.json_formatter = JSONFormatter()
        self.table_formatter = TableFormatter()

    def investigate(
        self,
        domain: str,
        keywords: Optional[List[str]] = None,
        keywords_file: Optional[str] = None,
        format: str = 'table',
        output_file: Optional[str] = None
    ) -> Dict:
        """Perform complete OSINT investigation on domain

        Args:
            domain: Domain to investigate
            keywords: List of keywords for email guessing
            keywords_file: Path to keywords file
            format: Output format ('table' or 'json')
            output_file: Optional output file path

        Returns:
            Results dictionary
        """
        # Normalize domain
        normalized_domain = normalize_domain(domain)

        if not normalized_domain:
            return {
                'error': f'Invalid domain: {domain}',
                'domain': domain
            }

        # Print banner for table format
        if format == 'table':
            self.table_formatter.print_banner()
            print(f"\nInvestigating: {normalized_domain}\n")

        # Initialize results
        results = {
            'domain': normalized_domain,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
            'rdap': None,
            'dns': None,
            'ct_subdomains': [],
            'web_findings': {},
            'guessed_emails': {},
            'email_validation': {},
            'risk_notes': [],
            'errors': []
        }

        # Collect RDAP data
        if format == 'table':
            print("Collecting RDAP/WHOIS data...")
        self.rate_limiter.wait()
        try:
            results['rdap'] = self.rdap_collector.collect(normalized_domain)
        except Exception as e:
            results['errors'].append(f'RDAP error: {str(e)}')

        # Collect DNS data
        if format == 'table':
            print("Querying DNS records...")
        self.rate_limiter.wait()
        try:
            results['dns'] = self.dns_collector.collect(normalized_domain)
        except Exception as e:
            results['errors'].append(f'DNS error: {str(e)}')

        # Collect CT subdomains
        if format == 'table':
            print("Searching Certificate Transparency logs...")
        self.rate_limiter.wait()
        try:
            subdomains = self.ct_collector.collect_subdomains(normalized_domain)
            results['ct_subdomains'] = list(subdomains)
        except Exception as e:
            results['errors'].append(f'CT error: {str(e)}')

        # Collect web data
        if format == 'table':
            print(f"Scraping public contact pages (max {self.max_pages})...")
        self.rate_limiter.wait()
        try:
            results['web_findings'] = self.web_collector.collect(normalized_domain)
        except Exception as e:
            results['errors'].append(f'Web scraping error: {str(e)}')

        # Generate guessed emails
        if format == 'table':
            print("Generating keyword-based email guesses...")
        try:
            results['guessed_emails'] = self._generate_guessed_emails(
                normalized_domain,
                keywords,
                keywords_file
            )
        except Exception as e:
            results['errors'].append(f'Email guessing error: {str(e)}')

        # Validate email domain
        if format == 'table':
            print("Validating email domain configuration...")
        try:
            results['email_validation'] = self._validate_email_domain(normalized_domain)
        except Exception as e:
            results['errors'].append(f'Email validation error: {str(e)}')

        # Generate risk notes
        results['risk_notes'] = self._generate_risk_notes(results)

        # Output results
        if format == 'json':
            json_output = self.json_formatter.format(results)
            if output_file:
                self.json_formatter.save_to_file(results, output_file)
                print(f"Results saved to {output_file}")
            else:
                print(json_output)
        else:
            # Table format
            self.table_formatter.print_summary(results)
            if output_file:
                self.json_formatter.save_to_file(results, output_file)
                print(f"JSON results also saved to {output_file}")

        return results

    def _generate_guessed_emails(
        self,
        domain: str,
        keywords: Optional[List[str]],
        keywords_file: Optional[str]
    ) -> Dict:
        """Generate guessed email addresses from keywords

        Args:
            domain: Domain to generate emails for
            keywords: List of keywords
            keywords_file: Path to keywords file

        Returns:
            Dictionary with guessed emails and metadata
        """
        # Determine which keywords to use
        final_keywords = DEFAULT_KEYWORDS.copy()

        if keywords:
            final_keywords.extend(keywords)

        if keywords_file:
            try:
                file_keywords = load_keywords_from_file(keywords_file)
                final_keywords.extend(file_keywords)
            except Exception as e:
                # Just use defaults if file fails
                pass

        # Remove duplicates
        final_keywords = list(set(final_keywords))

        # Generate emails
        guessed_emails = []
        for keyword in final_keywords:
            email = f"{keyword}@{domain}"
            if is_valid_email(email):
                guessed_emails.append(email)

        return {
            'emails': guessed_emails,
            'keywords_used': final_keywords,
            'note': 'These emails are GUESSED based on common keywords and are UNVERIFIED. '
                    'Domain-level checks (MX/SPF/DMARC) apply to the whole domain, not individual mailboxes.'
        }

    def _validate_email_domain(self, domain: str) -> Dict:
        """Validate email domain configuration (safe checks only)

        Only checks domain-level configuration:
        - MX records exist
        - SPF record present
        - DMARC record present

        Does NOT check if specific mailboxes exist.

        Args:
            domain: Domain to validate

        Returns:
            Dictionary with validation results
        """
        # Get DNS data
        dns_data = self.dns_collector.collect(domain)

        validation = {
            'domain_has_mx': False,
            'spf_present': False,
            'dmarc_present': False,
        }

        if dns_data:
            validation['domain_has_mx'] = len(dns_data.get('mx_records', [])) > 0
            validation['spf_present'] = dns_data.get('spf') is not None
            validation['dmarc_present'] = dns_data.get('dmarc') is not None

        return validation

    def _generate_risk_notes(self, results: Dict) -> List[str]:
        """Generate security risk notes based on findings

        Args:
            results: Investigation results

        Returns:
            List of risk observation strings
        """
        notes = []

        # Check email security
        email_val = results.get('email_validation', {})

        if not email_val.get('spf_present'):
            notes.append(
                "No SPF record found - domain is vulnerable to email spoofing. "
                "Blue team: Add SPF record to prevent email forgery."
            )

        if not email_val.get('dmarc_present'):
            notes.append(
                "No DMARC record found - no policy for handling failed SPF/DKIM. "
                "Blue team: Add DMARC record to protect domain reputation."
            )

        # Check subdomain exposure
        ct_subdomains = results.get('ct_subdomains', [])
        if len(ct_subdomains) > 20:
            notes.append(
                f"Large number of subdomains exposed ({len(ct_subdomains)}) in CT logs. "
                "Blue team: Review if all subdomains should be publicly discoverable."
            )

        # Check for dev/staging subdomains
        dev_patterns = ['dev', 'development', 'test', 'staging', 'stage', 'uat']
        dev_subdomains = [s for s in ct_subdomains if any(p in s.lower() for p in dev_patterns)]

        if dev_subdomains:
            notes.append(
                f"Development/staging subdomains found ({len(dev_subdomains)}). "
                "Blue team: Ensure these are properly secured and not exposing sensitive data."
            )

        # Check web findings
        web_findings = results.get('web_findings', {})
        if web_findings.get('emails'):
            notes.append(
                f"Public email addresses found ({len(web_findings['emails'])}). "
                "Blue team: Be aware these may receive spam/phishing."
            )

        return notes
