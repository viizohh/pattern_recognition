"""OSINT Module for Hound - Passive Domain Intelligence

This module provides passive OSINT capabilities for educational and defensive security purposes.

ETHICAL USE ONLY:
- This tool performs PASSIVE reconnaissance only
- Public DNS records, CT logs, and webpage scraping
- Domain-level email validation (MX/SPF/DMARC)
- NO mailbox verification or account enumeration
- NO credential testing or login attempts

Use responsibly. Respect rate limits. Obey laws.
"""

__version__ = "1.0.0"
__author__ = "Hound Security Team"

from .collectors.rdap import RDAPCollector
from .collectors.dns import DNSCollector
from .collectors.ct import CTCollector
from .collectors.web import WebCollector
from .parsers.emails import EmailParser
from .parsers.phones import PhoneParser
from .parsers.entities import EntityParser

__all__ = [
    "RDAPCollector",
    "DNSCollector",
    "CTCollector",
    "WebCollector",
    "EmailParser",
    "PhoneParser",
    "EntityParser",
]
