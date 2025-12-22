"""Breach Fetch Module for Hound - Check for data breaches

This module provides breach checking capabilities for educational and defensive purposes.

ETHICAL USE ONLY:
- Check only your own data or with explicit permission
- Do not use breach data for unauthorized access
- Results are intelligence, not proof of compromise
- Comply with data protection laws (GDPR, CCPA, etc.)

Use responsibly. Use legally. Protect privacy.
"""

__version__ = "1.0.0"
__author__ = "Hound Security Team"

from .password_checker import PasswordChecker
from .email_checker import EmailChecker
from .breach_database import BreachDatabase

__all__ = [
    "PasswordChecker",
    "EmailChecker",
    "BreachDatabase",
]
