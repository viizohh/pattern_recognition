"""Web scraper for public contact information

Scrapes publicly accessible contact pages to extract:
- Email addresses
- Phone numbers
- Names and organizations

Only accesses public pages - no authentication, no robots.txt violations.
"""

import requests
from bs4 import BeautifulSoup
from typing import Set, Dict, List
from urllib.parse import urljoin, urlparse
from net_watch.osint.parsers.emails import EmailParser
from net_watch.osint.parsers.phones import PhoneParser
from net_watch.osint.parsers.entities import EntityParser


class WebCollector:
    """Collect contact information from public webpages"""

    def __init__(self, timeout: int = 10, max_pages: int = 10):
        """Initialize web collector

        Args:
            timeout: HTTP request timeout in seconds
            max_pages: Maximum number of pages to scrape
        """
        self.timeout = timeout
        self.max_pages = max_pages
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Hound-OSINT/1.0 (Educational Security Research)',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })

        # Initialize parsers
        self.email_parser = EmailParser()
        self.phone_parser = PhoneParser()
        self.entity_parser = EntityParser()

        # Common contact page paths
        self.contact_paths = [
            '/',            # Homepage
            '/contact',
            '/contact-us',
            '/contactus',
            '/about',
            '/about-us',
            '/team',
            '/staff',
            '/people',
            '/legal',
            '/privacy',
            '/terms',
            '/support',
            '/help',
        ]

    def collect(self, domain: str, custom_paths: List[str] = None) -> Dict:
        """Collect contact information from domain's public pages

        Args:
            domain: Domain to scrape
            custom_paths: Optional custom paths to check

        Returns:
            Dictionary with collected emails, phones, names, etc.
        """
        results = {
            'domain': domain,
            'pages_checked': [],
            'pages_successful': [],
            'emails': set(),
            'phones': set(),
            'names': set(),
            'organizations': set(),
            'errors': []
        }

        # Determine which paths to check
        paths_to_check = self.contact_paths[:self.max_pages]
        if custom_paths:
            paths_to_check.extend(custom_paths)
            paths_to_check = paths_to_check[:self.max_pages]

        # Scrape each path
        for path in paths_to_check:
            url = self._build_url(domain, path)
            results['pages_checked'].append(url)

            try:
                page_data = self._scrape_page(url)

                if page_data:
                    results['pages_successful'].append(url)
                    results['emails'].update(page_data['emails'])
                    results['phones'].update(page_data['phones'])
                    results['names'].update(page_data['names'])
                    results['organizations'].update(page_data['organizations'])

            except Exception as e:
                results['errors'].append({'url': url, 'error': str(e)})

        # Convert sets to lists for JSON serialization
        results['emails'] = list(results['emails'])
        results['phones'] = list(results['phones'])
        results['names'] = list(results['names'])
        results['organizations'] = list(results['organizations'])

        return results

    def _build_url(self, domain: str, path: str) -> str:
        """Build full URL from domain and path

        Args:
            domain: Domain name
            path: URL path

        Returns:
            Full URL with https://
        """
        # Ensure domain doesn't have scheme
        domain = domain.replace('https://', '').replace('http://', '')

        # Build URL
        if path.startswith('/'):
            return f"https://{domain}{path}"
        else:
            return f"https://{domain}/{path}"

    def _scrape_page(self, url: str) -> Dict:
        """Scrape a single page for contact information

        Args:
            url: URL to scrape

        Returns:
            Dictionary with extracted data
        """
        try:
            # Fetch page
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)

            # Only process successful responses with HTML
            if response.status_code != 200:
                return None

            if 'text/html' not in response.headers.get('Content-Type', ''):
                return None

            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')

            # Remove script and style tags (they contain noise)
            for tag in soup(['script', 'style', 'noscript']):
                tag.decompose()

            # Get visible text
            text = soup.get_text(separator=' ', strip=True)

            # Also get HTML for mailto: links
            html = str(soup)

            # Extract information
            emails = self.email_parser.extract_from_html(html)
            emails.update(self.email_parser.extract_from_text(text))

            phones = self.phone_parser.extract_from_text(text)

            names = self.entity_parser.extract_names(text)

            organizations = self.entity_parser.extract_organizations(text)

            return {
                'emails': emails,
                'phones': phones,
                'names': names,
                'organizations': organizations,
            }

        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException:
            return None
        except Exception:
            return None

    def check_robots_txt(self, domain: str) -> str:
        """Check if domain has a robots.txt file

        Args:
            domain: Domain to check

        Returns:
            robots.txt content or error message
        """
        url = f"https://{domain}/robots.txt"

        try:
            response = self.session.get(url, timeout=self.timeout)
            if response.status_code == 200:
                return response.text
            else:
                return "No robots.txt found"
        except Exception:
            return "Error fetching robots.txt"

    def is_page_accessible(self, url: str) -> bool:
        """Check if a URL is accessible

        Args:
            url: URL to check

        Returns:
            True if page returns 200 OK
        """
        try:
            response = self.session.head(url, timeout=self.timeout, allow_redirects=True)
            return response.status_code == 200
        except Exception:
            return False
