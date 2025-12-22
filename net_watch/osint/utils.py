"""Utility functions for OSINT operations

Provides:
- Input normalization (domain validation, punycode handling)
- Rate limiting and polite mode
- Retry logic with exponential backoff
- User-agent handling
"""

import time
import re
from typing import Optional, List
from urllib.parse import urlparse
import tldextract


class RateLimiter:
    """Simple rate limiter to ensure polite scraping"""

    def __init__(self, delay: float = 1.0):
        """Initialize rate limiter

        Args:
            delay: Delay in seconds between requests (default: 1.0)
        """
        self.delay = delay
        self.last_request = 0

    def wait(self):
        """Wait if necessary to maintain rate limit"""
        if self.last_request > 0:
            elapsed = time.time() - self.last_request
            if elapsed < self.delay:
                time.sleep(self.delay - elapsed)
        self.last_request = time.time()


def normalize_domain(domain_input: str) -> Optional[str]:
    """Normalize domain input to clean domain name

    Handles:
    - Strips http://, https://, www.
    - Converts to lowercase
    - Handles punycode/unicode
    - Rejects IP addresses
    - Validates TLD

    Args:
        domain_input: Raw domain input from user

    Returns:
        Normalized domain string, or None if invalid

    Examples:
        "https://www.Example.com/path" -> "example.com"
        "EXAMPLE.COM" -> "example.com"
        "192.168.1.1" -> None (IP rejected)
    """
    if not domain_input:
        return None

    # Strip whitespace
    domain = domain_input.strip()

    # Remove scheme if present
    if '://' in domain:
        parsed = urlparse(domain)
        domain = parsed.netloc if parsed.netloc else parsed.path

    # Remove path if present
    domain = domain.split('/')[0]

    # Remove port if present
    domain = domain.split(':')[0]

    # Remove www. prefix
    if domain.lower().startswith('www.'):
        domain = domain[4:]

    # Convert to lowercase
    domain = domain.lower()

    # Check if it's an IP address (reject IPs)
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, domain):
        return None

    # Validate using tldextract
    extracted = tldextract.extract(domain)

    # Must have both domain and suffix (TLD)
    if not extracted.domain or not extracted.suffix:
        return None

    # Reconstruct clean domain
    if extracted.subdomain:
        normalized = f"{extracted.subdomain}.{extracted.domain}.{extracted.suffix}"
    else:
        normalized = f"{extracted.domain}.{extracted.suffix}"

    # Handle punycode (internationalized domains)
    try:
        # Try to encode as punycode if needed
        normalized.encode('ascii')
    except UnicodeEncodeError:
        # Contains non-ASCII, convert to punycode
        normalized = normalized.encode('idna').decode('ascii')

    return normalized


def is_valid_email(email: str) -> bool:
    """Check if email address has valid syntax

    Does NOT check if mailbox exists (that would be active reconnaissance).
    Only validates format.

    Args:
        email: Email address to validate

    Returns:
        True if syntax is valid, False otherwise
    """
    # RFC 5322 simplified pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email.lower()))


def get_user_agent() -> str:
    """Get user agent string for HTTP requests

    Returns:
        User agent string identifying hound
    """
    return "Hound-OSINT/1.0 (Educational Security Research; +https://github.com/hound)"


def extract_domain_from_email(email: str) -> Optional[str]:
    """Extract domain from email address

    Args:
        email: Email address

    Returns:
        Domain part of email, or None if invalid

    Example:
        "admin@example.com" -> "example.com"
    """
    if '@' not in email:
        return None

    parts = email.split('@')
    if len(parts) != 2:
        return None

    return parts[1].lower()


def load_keywords_from_file(file_path: str) -> List[str]:
    """Load keywords from a text file

    Reads one keyword per line, strips whitespace, ignores empty lines and comments.

    Args:
        file_path: Path to keywords file

    Returns:
        List of keywords

    Example file format:
        # Common email prefixes
        security
        admin
        support
        # Press contacts
        press
        media
    """
    keywords = []

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                # Strip whitespace
                line = line.strip()

                # Skip empty lines and comments
                if not line or line.startswith('#'):
                    continue

                # Add keyword
                keywords.append(line.lower())

        return keywords

    except FileNotFoundError:
        raise ValueError(f"Keywords file not found: {file_path}")
    except Exception as e:
        raise ValueError(f"Error reading keywords file: {e}")


# Default keywords for email guessing
DEFAULT_KEYWORDS = [
    "info",
    "contact",
    "support",
    "admin",
    "security",
    "abuse",
    "hello",
    "team",
    "help",
    "sales",
    "press",
    "media",
    "legal",
    "privacy",
    "hr",
    "jobs",
    "careers",
]
