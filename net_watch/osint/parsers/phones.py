"""Phone number extraction

Extracts phone numbers from text using various formats.
Handles international and US formats.
"""

import re
from typing import Set


class PhoneParser:
    """Extract phone numbers from text"""

    def __init__(self):
        # Pattern for phone numbers (handles many formats)
        # Matches: +1-555-123-4567, (555) 123-4567, 555.123.4567, etc.
        self.phone_patterns = [
            # International format: +1-555-123-4567 or +44 20 7123 4567
            re.compile(r'\+\d{1,3}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,9}'),

            # US format: (555) 123-4567 or 555-123-4567
            re.compile(r'\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}'),

            # Simple format: 555.123.4567
            re.compile(r'\d{3}[.\s-]\d{3}[.\s-]\d{4}'),
        ]

        # Minimum length for valid phone number
        self.min_length = 10

    def extract_from_text(self, text: str) -> Set[str]:
        """Extract phone numbers from text

        Args:
            text: Text to search

        Returns:
            Set of phone numbers found
        """
        if not text:
            return set()

        phones = set()

        for pattern in self.phone_patterns:
            matches = pattern.findall(text)
            for match in matches:
                # Clean up the number
                cleaned = self._clean_phone(match)

                # Validate length
                if len(cleaned) >= self.min_length:
                    phones.add(match.strip())  # Keep original format

        return phones

    def _clean_phone(self, phone: str) -> str:
        """Remove formatting characters from phone number

        Args:
            phone: Phone number with formatting

        Returns:
            Digits only

        Example:
            "+1-555-123-4567" -> "15551234567"
        """
        return re.sub(r'[^\d]', '', phone)

    def normalize_phone(self, phone: str) -> str:
        """Normalize phone number to clean format

        Args:
            phone: Raw phone number

        Returns:
            Normalized phone number

        Example:
            "(555) 123-4567" -> "+1-555-123-4567"
        """
        digits = self._clean_phone(phone)

        # If it's a 10-digit US number, add +1
        if len(digits) == 10:
            return f"+1-{digits[0:3]}-{digits[3:6]}-{digits[6:]}"

        # If it already has country code
        if len(digits) == 11 and digits[0] == '1':
            return f"+{digits[0]}-{digits[1:4]}-{digits[4:7]}-{digits[7:]}"

        # International format - just return original
        return phone
