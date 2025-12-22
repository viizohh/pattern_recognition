"""Email and domain breach checker

Checks if an email address or domain appears in known data breaches.
Uses local breach database - no external API calls needed.
"""

from typing import List, Dict
from net_watch.breach.breach_database import BreachDatabase


class EmailChecker:
    """Check if email/domain appears in known breaches"""

    def __init__(self):
        """Initialize email checker with breach database"""
        self.breach_db = BreachDatabase()

    def check_email(self, email: str) -> Dict:
        """Check if email address appears in known breaches

        Args:
            email: Email address to check

        Returns:
            Dictionary with results:
            {
                'email': str,
                'breaches': List[Dict],
                'total_breaches': int,
                'confidence': float,
                'recommendation': str
            }
        """
        email = email.lower().strip()

        # Validate email format
        if '@' not in email:
            return {
                'email': email,
                'breaches': [],
                'total_breaches': 0,
                'confidence': 0.0,
                'error': 'Invalid email format'
            }

        # Search breach database
        breaches = self.breach_db.search_by_email(email)

        # Calculate confidence score
        # Higher confidence if domain is in specific breach list (not wildcard)
        confidence = self._calculate_confidence(email, breaches)

        # Generate recommendation
        recommendation = self._generate_recommendation(breaches)

        return {
            'email': email,
            'breaches': breaches,
            'total_breaches': len(breaches),
            'confidence': confidence,
            'recommendation': recommendation
        }

    def check_domain(self, domain: str) -> Dict:
        """Check if domain appears in known breaches

        Args:
            domain: Domain to check

        Returns:
            Dictionary with results similar to check_email()
        """
        domain = domain.lower().strip()

        # Remove protocol if present
        domain = domain.replace('https://', '').replace('http://', '')
        domain = domain.split('/')[0]  # Remove path

        # Search breach database
        breaches = self.breach_db.search_by_domain(domain)

        confidence = self._calculate_confidence(domain, breaches)
        recommendation = self._generate_recommendation(breaches)

        return {
            'domain': domain,
            'breaches': breaches,
            'total_breaches': len(breaches),
            'confidence': confidence,
            'recommendation': recommendation
        }

    def check_username(self, username: str) -> Dict:
        """Check breaches that exposed username data

        Note: This doesn't check if specific username was breached,
        but shows breaches that included username fields.

        Args:
            username: Username to check

        Returns:
            Dictionary with breaches that exposed usernames
        """
        breaches = self.breach_db.search_by_username(username)

        return {
            'username': username,
            'breaches': breaches,
            'total_breaches': len(breaches),
            'note': 'These breaches exposed username data. Your specific username may or may not be included.',
            'recommendation': self._generate_recommendation(breaches)
        }

    def check_phone(self, phone: str) -> Dict:
        """Check breaches that exposed phone number data

        Note: This doesn't check if specific phone was breached,
        but shows breaches that included phone number fields.

        Args:
            phone: Phone number to check

        Returns:
            Dictionary with breaches that exposed phone numbers
        """
        breaches = self.breach_db.search_by_phone(phone)

        return {
            'phone': phone,
            'breaches': breaches,
            'total_breaches': len(breaches),
            'note': 'These breaches exposed phone number data. Your specific number may or may not be included.',
            'recommendation': self._generate_recommendation(breaches)
        }

    def _calculate_confidence(self, query: str, breaches: List[Dict]) -> float:
        """Calculate confidence score for breach match

        Args:
            query: Email/domain queried
            breaches: List of matching breaches

        Returns:
            Confidence score (0-100)
        """
        if not breaches:
            return 0.0

        # All matches are domain-specific (wildcards excluded)
        # Confidence is high (90%) for domain-level match
        # Note: This does NOT mean the specific email was breached,
        # only that the domain (e.g., @yahoo.com) was affected
        return 90.0

    def _generate_recommendation(self, breaches: List[Dict]) -> str:
        """Generate recommendation based on breaches found

        Args:
            breaches: List of breaches found

        Returns:
            Human-readable recommendation
        """
        if not breaches:
            return "No known breaches found for this query in our database."

        total_breaches = len(breaches)

        # Check for recent breaches (within last 5 years)
        from datetime import datetime, timedelta
        recent_threshold = datetime.now() - timedelta(days=365*5)
        recent_breaches = sum(
            1 for b in breaches
            if datetime.strptime(b['date'], '%Y-%m-%d') > recent_threshold
        )

        # Check for critical severity
        critical_breaches = sum(1 for b in breaches if b.get('severity') == 'critical')

        recommendations = []

        if critical_breaches > 0:
            recommendations.append(f"[!] {critical_breaches} CRITICAL breach(es) found!")

        if recent_breaches > 0:
            recommendations.append(f"WARNING: {recent_breaches} recent breach(es) (last 5 years)")

        recommendations.append(f"Total {total_breaches} breach(es) found")
        recommendations.append("Recommended actions:")
        recommendations.append("   * Change passwords immediately")
        recommendations.append("   * Enable 2FA/MFA if not already enabled")
        recommendations.append("   * Monitor accounts for suspicious activity")
        recommendations.append("   * Check credit reports if financial data was exposed")

        return '\n'.join(recommendations)

    def get_database_stats(self) -> Dict:
        """Get statistics about the breach database

        Returns:
            Dictionary with database statistics
        """
        return {
            'total_breaches': self.breach_db.get_breach_count(),
            'total_records': self.breach_db.get_total_records(),
            'note': 'This database contains metadata for major known breaches. '
                    'Not all breaches are included - this is for educational purposes only.'
        }
