"""Email extraction and validation

Extracts email addresses from text and performs domain-level validation.

SAFETY: Only performs domain-level checks (MX records, SPF/DMARC).
Does NOT verify if specific mailboxes exist.
"""

import re
from typing import List, Set
from net_watch.osint.utils import is_valid_email, extract_domain_from_email


class EmailParser:
    """Extract and validate email addresses from text"""

    def __init__(self):
        # Robust email regex pattern
        # Matches most valid email formats
        self.email_pattern = re.compile(
            r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b',
            re.IGNORECASE
        )

        # Common false positives to exclude
        self.exclude_patterns = [
            r'.*@example\.(com|org|net)',  # Example emails
            r'.*@localhost',                # Localhost
            r'.*@\d+\.\d+\.\d+\.\d+',      # IP addresses
            r'.*\.(png|jpg|gif|css|js)@',  # File extensions
        ]

    def extract_from_text(self, text: str) -> Set[str]:
        """Extract email addresses from text

        Args:
            text: Text to search for emails

        Returns:
            Set of unique, valid email addresses found
        """
        if not text:
            return set()

        # Find all potential emails
        potential_emails = self.email_pattern.findall(text)

        # Validate and filter
        valid_emails = set()
        for email in potential_emails:
            email_lower = email.lower()

            # Check if it's a known false positive
            if self._is_false_positive(email_lower):
                continue

            # Validate syntax
            if is_valid_email(email_lower):
                valid_emails.add(email_lower)

        return valid_emails

    def _is_false_positive(self, email: str) -> bool:
        """Check if email matches common false positive patterns

        Args:
            email: Email to check

        Returns:
            True if likely a false positive
        """
        for pattern in self.exclude_patterns:
            if re.match(pattern, email):
                return True
        return False

    def extract_from_html(self, html: str) -> Set[str]:
        """Extract emails from HTML content

        Handles mailto: links and plain text emails in HTML

        Args:
            html: HTML content

        Returns:
            Set of unique email addresses
        """
        if not html:
            return set()

        emails = set()

        # Extract from mailto: links
        mailto_pattern = re.compile(r'mailto:([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', re.IGNORECASE)
        mailto_emails = mailto_pattern.findall(html)
        for email in mailto_emails:
            if is_valid_email(email.lower()):
                emails.add(email.lower())

        # Extract from plain text in HTML
        text_emails = self.extract_from_text(html)
        emails.update(text_emails)

        return emails

    def group_by_domain(self, emails: Set[str]) -> dict:
        """Group emails by their domain

        Args:
            emails: Set of email addresses

        Returns:
            Dictionary mapping domains to lists of emails

        Example:
            {"example.com": ["admin@example.com", "info@example.com"]}
        """
        grouped = {}

        for email in emails:
            domain = extract_domain_from_email(email)
            if domain:
                if domain not in grouped:
                    grouped[domain] = []
                grouped[domain].append(email)

        return grouped
