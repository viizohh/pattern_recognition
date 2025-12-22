"""RDAP (Registration Data Access Protocol) collector

RDAP is the modern replacement for WHOIS, providing structured JSON
data about domain registration.

Collects:
- Registrar information
- Registration dates
- Nameservers
- Status
- Contact information (if publicly available)
"""

import requests
from typing import Optional, Dict
from datetime import datetime


class RDAPCollector:
    """Collect domain registration data via RDAP"""

    def __init__(self, timeout: int = 10):
        """Initialize RDAP collector

        Args:
            timeout: HTTP request timeout in seconds
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Hound-OSINT/1.0 (Educational Security Research)',
            'Accept': 'application/json'
        })

        # RDAP bootstrap service
        self.bootstrap_url = "https://rdap-bootstrap.arin.net/bootstrap/domain/{}"

    def collect(self, domain: str) -> Optional[Dict]:
        """Collect RDAP information for domain

        Args:
            domain: Domain to query

        Returns:
            Dictionary with RDAP data or None if unavailable
        """
        try:
            # Query RDAP bootstrap service
            url = self.bootstrap_url.format(domain)
            response = self.session.get(url, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                return self._parse_rdap_response(data, domain)
            else:
                return None

        except requests.exceptions.Timeout:
            return {'error': 'RDAP query timed out'}
        except requests.exceptions.RequestException as e:
            return {'error': f'RDAP query failed: {str(e)}'}
        except Exception as e:
            return {'error': f'RDAP parsing error: {str(e)}'}

    def _parse_rdap_response(self, data: dict, domain: str) -> Dict:
        """Parse RDAP JSON response into simplified format

        Args:
            data: Raw RDAP JSON response
            domain: Domain queried

        Returns:
            Simplified dictionary with key information
        """
        result = {
            'domain': domain,
            'status': data.get('status', []),
            'nameservers': [],
            'registrar': None,
            'created': None,
            'updated': None,
            'expires': None,
            'contacts': {
                'registrant': None,
                'administrative': None,
                'technical': None,
            },
            'raw_rdap': data  # Keep raw data for advanced users
        }

        # Extract nameservers
        if 'nameservers' in data:
            for ns in data['nameservers']:
                if 'ldhName' in ns:
                    result['nameservers'].append(ns['ldhName'])

        # Extract dates (events)
        if 'events' in data:
            for event in data['events']:
                event_action = event.get('eventAction', '')
                event_date = event.get('eventDate', '')

                if event_action == 'registration':
                    result['created'] = self._parse_date(event_date)
                elif event_action == 'last changed':
                    result['updated'] = self._parse_date(event_date)
                elif event_action == 'expiration':
                    result['expires'] = self._parse_date(event_date)

        # Extract registrar from entities
        if 'entities' in data:
            for entity in data['entities']:
                roles = entity.get('roles', [])

                if 'registrar' in roles:
                    # Get registrar name from vcard
                    vcard = entity.get('vcardArray', [])
                    result['registrar'] = self._extract_org_from_vcard(vcard)

                # Extract contact information
                if 'registrant' in roles:
                    vcard = entity.get('vcardArray', [])
                    result['contacts']['registrant'] = self._extract_contact_from_vcard(vcard)
                elif 'administrative' in roles:
                    vcard = entity.get('vcardArray', [])
                    result['contacts']['administrative'] = self._extract_contact_from_vcard(vcard)
                elif 'technical' in roles:
                    vcard = entity.get('vcardArray', [])
                    result['contacts']['technical'] = self._extract_contact_from_vcard(vcard)

        return result

    def _parse_date(self, date_str: str) -> Optional[str]:
        """Parse ISO 8601 date string to readable format

        Args:
            date_str: ISO 8601 date string

        Returns:
            Formatted date string or None
        """
        if not date_str:
            return None

        try:
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            return dt.strftime('%Y-%m-%d')
        except Exception:
            return date_str

    def _extract_org_from_vcard(self, vcard: list) -> Optional[str]:
        """Extract organization name from vCard

        Args:
            vcard: vCard array from RDAP response

        Returns:
            Organization name or None
        """
        if not vcard or len(vcard) < 2:
            return None

        # vCard format: [["version", {}, "text", "4.0"], ["fn", {}, "text", "Org Name"], ...]
        for field in vcard[1]:
            if isinstance(field, list) and len(field) >= 4:
                if field[0] in ['fn', 'org']:
                    return field[3]

        return None

    def _extract_contact_from_vcard(self, vcard: list) -> Optional[Dict]:
        """Extract contact information from vCard

        Args:
            vcard: vCard array from RDAP response

        Returns:
            Dictionary with contact info or None
        """
        if not vcard or len(vcard) < 2:
            return None

        contact = {
            'name': None,
            'organization': None,
            'email': None,
        }

        for field in vcard[1]:
            if isinstance(field, list) and len(field) >= 4:
                field_type = field[0]
                field_value = field[3]

                if field_type == 'fn':
                    contact['name'] = field_value
                elif field_type == 'org':
                    contact['organization'] = field_value
                elif field_type == 'email':
                    contact['email'] = field_value

        # Only return if we got at least some information
        if any(contact.values()):
            return contact
        return None

    def is_available(self, domain: str) -> bool:
        """Check if RDAP data is available for domain

        Args:
            domain: Domain to check

        Returns:
            True if RDAP data available
        """
        result = self.collect(domain)
        return result is not None and 'error' not in result
