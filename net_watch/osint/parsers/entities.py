"""Entity extraction - names and organizations

Extracts person names and organization names from text using heuristics.
"""

import re
from typing import Set, List


class EntityParser:
    """Extract names and organizations from text"""

    def __init__(self):
        # Common title patterns that indicate names
        self.title_patterns = [
            r'\b(Mr|Mrs|Ms|Dr|Prof|Professor|CEO|CTO|CFO|Director|Manager)\.?\s+([A-Z][a-z]+\s+[A-Z][a-z]+)',
        ]

        # Patterns for organization indicators
        self.org_indicators = [
            'Inc', 'LLC', 'Ltd', 'Corporation', 'Corp', 'Company', 'Co',
            'Limited', 'Foundation', 'Institute', 'Association', 'Group',
            'Partners', 'Ventures', 'Technologies', 'Systems', 'Solutions'
        ]

        # Common first names (helps identify person names)
        self.common_first_names = {
            'john', 'jane', 'michael', 'sarah', 'david', 'emily',
            'james', 'mary', 'robert', 'jennifer', 'william', 'linda'
        }

    def extract_names(self, text: str) -> Set[str]:
        """Extract person names from text

        Uses heuristics:
        - Title + Name pattern (Dr. John Smith)
        - Capitalized words near "Contact:", "By:", "Author:"
        - Two consecutive capitalized words

        Args:
            text: Text to search

        Returns:
            Set of potential person names
        """
        if not text:
            return set()

        names = set()

        # Extract from title patterns
        for pattern in self.title_patterns:
            matches = re.findall(pattern, text)
            for match in matches:
                if isinstance(match, tuple):
                    # match[1] is the name part
                    names.add(match[1])

        # Extract from contact contexts
        contact_pattern = r'(?:Contact|By|Author|Written by):\s*([A-Z][a-z]+\s+[A-Z][a-z]+)'
        matches = re.findall(contact_pattern, text)
        names.update(matches)

        # Extract consecutive capitalized words (likely names)
        # But filter out all-caps (likely headings)
        cap_words_pattern = r'\b([A-Z][a-z]+\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b'
        matches = re.findall(cap_words_pattern, text)

        for match in matches:
            # Skip if it's an organization indicator
            if any(org in match for org in self.org_indicators):
                continue

            # Check if first word looks like a common first name
            first_word = match.split()[0].lower()
            if first_word in self.common_first_names:
                names.add(match)

        return names

    def extract_organizations(self, text: str) -> Set[str]:
        """Extract organization names from text

        Uses heuristics:
        - Capitalized words followed by org indicators (Inc, LLC, etc.)
        - Copyright statements
        - "About [Company]" patterns

        Args:
            text: Text to search

        Returns:
            Set of potential organization names
        """
        if not text:
            return set()

        orgs = set()

        # Pattern: Company Name + Org Indicator
        # e.g., "Acme Corp", "Example Inc.", "Tech Solutions LLC"
        for indicator in self.org_indicators:
            # Allow multiple words before indicator
            pattern = rf'\b([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*)\s+{indicator}\.?\b'
            matches = re.findall(pattern, text)
            for match in matches:
                orgs.add(f"{match} {indicator}")

        # Extract from copyright statements
        # e.g., "© 2024 Example Corporation"
        copyright_pattern = r'©\s*\d{4}\s+([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*(?:\s+(?:Inc|LLC|Ltd|Corp|Company|Co))?)'
        matches = re.findall(copyright_pattern, text)
        orgs.update(matches)

        # Extract from "About [Company]" or "[Company] is a"
        about_pattern = r'(?:About|Welcome to)\s+([A-Z][A-Za-z]+(?:\s+[A-Z][A-Za-z]+)*)'
        matches = re.findall(about_pattern, text)

        # Only add if it looks like an org (has multiple words or ends with indicator)
        for match in matches:
            if len(match.split()) > 1 or any(ind in match for ind in self.org_indicators):
                orgs.add(match)

        return orgs

    def extract_from_rdap(self, rdap_data: dict) -> dict:
        """Extract entities from RDAP/WHOIS data

        Args:
            rdap_data: RDAP response dictionary

        Returns:
            Dictionary with registrant, admin, tech contacts
        """
        entities = {
            'registrant': None,
            'admin': None,
            'technical': None,
            'organization': None
        }

        if not rdap_data or 'entities' not in rdap_data:
            return entities

        # RDAP structure: entities with roles
        for entity in rdap_data.get('entities', []):
            roles = entity.get('roles', [])

            # Extract name from vcard if available
            vcard = entity.get('vcardArray', [])
            name = self._extract_name_from_vcard(vcard)

            if 'registrant' in roles:
                entities['registrant'] = name
            elif 'administrative' in roles:
                entities['admin'] = name
            elif 'technical' in roles:
                entities['technical'] = name

        return entities

    def _extract_name_from_vcard(self, vcard: list) -> str:
        """Extract name from RDAP vCard format

        Args:
            vcard: vCard array from RDAP response

        Returns:
            Name string or 'Unknown'
        """
        if not vcard or len(vcard) < 2:
            return 'Unknown'

        # vCard format: [["version", {}, "text", "4.0"], ["fn", {}, "text", "John Smith"], ...]
        for field in vcard[1]:
            if isinstance(field, list) and len(field) >= 4:
                if field[0] == 'fn':  # Full name
                    return field[3]
                elif field[0] == 'org':  # Organization
                    return field[3]

        return 'Unknown'
