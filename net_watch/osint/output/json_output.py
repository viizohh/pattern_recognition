"""JSON output formatter for OSINT results"""

import json
from datetime import datetime
from typing import Dict, Any


class JSONFormatter:
    """Format OSINT results as JSON"""

    def __init__(self, pretty: bool = True):
        """Initialize JSON formatter

        Args:
            pretty: Whether to pretty-print JSON (default: True)
        """
        self.pretty = pretty

    def format(self, results: Dict[str, Any]) -> str:
        """Format results as JSON string

        Args:
            results: OSINT results dictionary

        Returns:
            JSON string
        """
        # Add timestamp if not present
        if 'timestamp' not in results:
            results['timestamp'] = datetime.utcnow().isoformat() + 'Z'

        # Convert sets to lists for JSON serialization
        results = self._convert_sets_to_lists(results)

        if self.pretty:
            return json.dumps(results, indent=2, sort_keys=False, ensure_ascii=False)
        else:
            return json.dumps(results, ensure_ascii=False)

    def _convert_sets_to_lists(self, obj: Any) -> Any:
        """Recursively convert sets to lists for JSON serialization

        Args:
            obj: Object to convert

        Returns:
            Object with sets converted to lists
        """
        if isinstance(obj, set):
            return sorted(list(obj))
        elif isinstance(obj, dict):
            return {key: self._convert_sets_to_lists(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._convert_sets_to_lists(item) for item in obj]
        else:
            return obj

    def save_to_file(self, results: Dict[str, Any], filename: str):
        """Save results to JSON file

        Args:
            results: OSINT results dictionary
            filename: Output filename
        """
        json_str = self.format(results)

        with open(filename, 'w', encoding='utf-8') as f:
            f.write(json_str)

    def create_schema(self) -> Dict:
        """Return the expected JSON schema

        Returns:
            Dictionary describing the JSON schema
        """
        return {
            "domain": "string - Target domain",
            "timestamp": "string - ISO 8601 timestamp",
            "rdap": {
                "domain": "string",
                "status": ["array of strings"],
                "registrar": "string or null",
                "created": "string (YYYY-MM-DD) or null",
                "updated": "string (YYYY-MM-DD) or null",
                "expires": "string (YYYY-MM-DD) or null",
                "nameservers": ["array of strings"],
                "contacts": {
                    "registrant": "object or null",
                    "administrative": "object or null",
                    "technical": "object or null"
                }
            },
            "dns": {
                "a_records": ["array of IP addresses"],
                "aaaa_records": ["array of IPv6 addresses"],
                "ns_records": ["array of nameservers"],
                "mx_records": ["array of {priority, host}"],
                "txt_records": ["array of strings"],
                "soa_record": "object or null",
                "spf": "string or null",
                "dmarc": "string or null",
                "dkim_hints": ["array of strings"]
            },
            "ct_subdomains": ["array of subdomains found in CT logs"],
            "web_findings": {
                "pages_checked": ["array of URLs"],
                "pages_successful": ["array of URLs"],
                "emails": ["array of email addresses"],
                "phones": ["array of phone numbers"],
                "names": ["array of person names"],
                "organizations": ["array of organization names"]
            },
            "guessed_emails": {
                "emails": ["array of guessed emails"],
                "keywords_used": ["array of keywords"],
                "note": "These emails are GUESSED and unverified"
            },
            "email_validation": {
                "domain_has_mx": "boolean",
                "spf_present": "boolean",
                "dmarc_present": "boolean"
            },
            "risk_notes": ["array of security observations"],
            "errors": ["array of error messages"]
        }
