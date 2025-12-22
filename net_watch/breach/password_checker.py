"""Password breach checker using HIBP Pwned Passwords API

Uses k-anonymity to check if a password has been compromised without
revealing the full password hash to the API.

How it works:
1. Hash password with SHA-1
2. Send only first 5 characters of hash to HIBP API
3. Receive list of all hashes starting with those 5 chars
4. Check if full hash appears in the list locally

This ensures the password is never sent over the network.

NO API KEY REQUIRED - this is a free public service!
"""

import hashlib
import requests
from typing import Optional, Dict


class PasswordChecker:
    """Check if password appears in known breach databases"""

    def __init__(self, timeout: int = 10):
        """Initialize password checker

        Args:
            timeout: Request timeout in seconds
        """
        self.timeout = timeout
        self.api_url = "https://api.pwnedpasswords.com/range/"
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Hound-Breach-Checker/1.0 (Educational Security Tool)',
            'Add-Padding': 'true'  # HIBP padding feature for extra privacy
        })

    def check_password(self, password: str) -> Dict:
        """Check if password has been compromised

        Uses k-anonymity to preserve privacy - only first 5 chars of hash are sent.

        Args:
            password: Password to check

        Returns:
            Dictionary with results:
            {
                'compromised': bool,
                'occurrences': int,
                'hash_prefix': str,
                'error': str (if error occurred)
            }
        """
        if not password:
            return {
                'compromised': False,
                'occurrences': 0,
                'error': 'Empty password provided'
            }

        try:
            # Hash the password with SHA-1
            sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

            # Split into prefix (first 5 chars) and suffix
            hash_prefix = sha1_hash[:5]
            hash_suffix = sha1_hash[5:]

            # Query HIBP API with only the prefix
            response = self.session.get(
                f"{self.api_url}{hash_prefix}",
                timeout=self.timeout
            )

            if response.status_code != 200:
                return {
                    'compromised': False,
                    'occurrences': 0,
                    'error': f'API returned status code {response.status_code}'
                }

            # Parse response - each line is: <hash_suffix>:<count>
            for line in response.text.splitlines():
                parts = line.split(':')
                if len(parts) != 2:
                    continue

                response_suffix, count = parts[0], int(parts[1])

                # Check if this matches our full hash
                if response_suffix == hash_suffix:
                    return {
                        'compromised': True,
                        'occurrences': count,
                        'hash_prefix': hash_prefix,
                        'severity': self._get_severity(count)
                    }

            # Hash not found - password is safe (as far as we know)
            return {
                'compromised': False,
                'occurrences': 0,
                'hash_prefix': hash_prefix
            }

        except requests.exceptions.Timeout:
            return {
                'compromised': False,
                'occurrences': 0,
                'error': 'Request timed out'
            }
        except requests.exceptions.RequestException as e:
            return {
                'compromised': False,
                'occurrences': 0,
                'error': f'Network error: {str(e)}'
            }
        except Exception as e:
            return {
                'compromised': False,
                'occurrences': 0,
                'error': f'Unexpected error: {str(e)}'
            }

    def _get_severity(self, occurrences: int) -> str:
        """Determine severity based on how many times password was seen

        Args:
            occurrences: Number of times password appeared in breaches

        Returns:
            Severity level: critical, high, medium, low
        """
        if occurrences > 100000:
            return "critical"
        elif occurrences > 10000:
            return "high"
        elif occurrences > 1000:
            return "medium"
        else:
            return "low"

    def get_password_strength_advice(self, result: Dict) -> str:
        """Get advice based on password check result

        Args:
            result: Result from check_password()

        Returns:
            Human-readable advice string
        """
        if result.get('error'):
            return "Unable to check password - please try again"

        if not result['compromised']:
            return "Password not found in known breaches (but still use a unique, strong password)"

        occurrences = result['occurrences']
        severity = result.get('severity', 'unknown')

        if severity == 'critical':
            return f"CRITICAL: This password has been seen {occurrences:,} times in breaches! Change immediately!"
        elif severity == 'high':
            return f"HIGH RISK: This password has been seen {occurrences:,} times in breaches. Change it now."
        elif severity == 'medium':
            return f"MEDIUM RISK: This password has been seen {occurrences:,} times in breaches. Change recommended."
        else:
            return f"LOW RISK: This password has been seen {occurrences:,} times in breaches. Consider changing."

    def is_password_safe(self, password: str) -> bool:
        """Simple boolean check if password is safe

        Args:
            password: Password to check

        Returns:
            True if password is safe, False if compromised
        """
        result = self.check_password(password)
        return not result['compromised']
