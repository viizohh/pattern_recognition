"""Breach database - Known major data breaches

This database contains metadata about major known data breaches.
Data is sourced from public breach disclosure reports and news.

NO ACTUAL LEAKED DATA IS STORED - only breach metadata.
"""

from typing import List, Dict, Optional
from datetime import datetime


class BreachDatabase:
    """Database of known major data breaches"""

    def __init__(self):
        """Initialize breach database with known breaches"""
        self.breaches = self._load_breach_data()

    def _load_breach_data(self) -> List[Dict]:
        """Load breach metadata

        Returns:
            List of breach dictionaries with metadata
        """
        # Major known breaches (public information)
        return [
            {
                "name": "Adobe",
                "date": "2013-10-04",
                "records": 153000000,
                "data_exposed": ["Email", "Password (hashed)", "Username"],
                "domains": ["adobe.com"],
                "description": "Adobe user database breach exposing 153 million records",
                "severity": "high",
                "source": "Public disclosure"
            },
            {
                "name": "LinkedIn",
                "date": "2012-06-05",
                "records": 165000000,
                "data_exposed": ["Email", "Password (hashed)"],
                "domains": ["linkedin.com"],
                "description": "LinkedIn breach with 165 million email and password combinations",
                "severity": "high",
                "source": "Public disclosure"
            },
            {
                "name": "Yahoo",
                "date": "2013-08-01",
                "records": 3000000000,
                "data_exposed": ["Email", "Password (hashed)", "Name", "Phone", "DOB", "Security Q&A"],
                "domains": ["yahoo.com", "ymail.com"],
                "description": "Massive Yahoo breach affecting 3 billion accounts",
                "severity": "critical",
                "source": "Public disclosure"
            },
            {
                "name": "Dropbox",
                "date": "2012-07-01",
                "records": 68000000,
                "data_exposed": ["Email", "Password (hashed)"],
                "domains": ["dropbox.com"],
                "description": "Dropbox user credentials stolen",
                "severity": "high",
                "source": "Public disclosure"
            },
            {
                "name": "MySpace",
                "date": "2013-06-11",
                "records": 360000000,
                "data_exposed": ["Email", "Password (hashed)", "Username"],
                "domains": ["myspace.com"],
                "description": "MySpace suffered massive breach of 360 million accounts",
                "severity": "high",
                "source": "Public disclosure"
            },
            {
                "name": "Equifax",
                "date": "2017-07-29",
                "records": 147000000,
                "data_exposed": ["Name", "SSN", "DOB", "Address", "Credit Card"],
                "domains": ["equifax.com"],
                "description": "Major credit reporting agency breach exposing sensitive financial data",
                "severity": "critical",
                "source": "Public disclosure"
            },
            {
                "name": "Target",
                "date": "2013-12-19",
                "records": 110000000,
                "data_exposed": ["Credit Card", "Name", "Email", "Phone"],
                "domains": ["target.com"],
                "description": "Retail breach exposing customer payment information",
                "severity": "high",
                "source": "Public disclosure"
            },
            {
                "name": "Uber",
                "date": "2016-10-01",
                "records": 57000000,
                "data_exposed": ["Email", "Name", "Phone", "Driver's License"],
                "domains": ["uber.com"],
                "description": "Uber breach affecting riders and drivers",
                "severity": "high",
                "source": "Public disclosure"
            },
            {
                "name": "Facebook",
                "date": "2019-04-03",
                "records": 533000000,
                "data_exposed": ["Email", "Phone", "Name", "Location", "DOB"],
                "domains": ["facebook.com", "fb.com"],
                "description": "Facebook data scraping incident affecting 533 million users",
                "severity": "high",
                "source": "Public disclosure"
            },
            {
                "name": "Twitter",
                "date": "2022-12-01",
                "records": 5400000,
                "data_exposed": ["Email", "Phone", "Username"],
                "domains": ["twitter.com", "x.com"],
                "description": "Twitter API vulnerability exposing user data",
                "severity": "medium",
                "source": "Public disclosure"
            },
            {
                "name": "Marriott/Starwood",
                "date": "2018-09-10",
                "records": 500000000,
                "data_exposed": ["Email", "Name", "Phone", "Passport", "Address", "Payment Card"],
                "domains": ["marriott.com", "starwoodhotels.com"],
                "description": "Marriott hotel chain breach exposing guest records",
                "severity": "critical",
                "source": "Public disclosure"
            },
            {
                "name": "Capital One",
                "date": "2019-03-22",
                "records": 106000000,
                "data_exposed": ["Name", "Address", "Credit Score", "SSN", "Bank Account"],
                "domains": ["capitalone.com"],
                "description": "Capital One data breach exposing customer financial data",
                "severity": "critical",
                "source": "Public disclosure"
            },
            {
                "name": "Anthem",
                "date": "2015-02-04",
                "records": 80000000,
                "data_exposed": ["Name", "SSN", "DOB", "Address", "Employment Info"],
                "domains": ["anthem.com"],
                "description": "Health insurance provider breach",
                "severity": "critical",
                "source": "Public disclosure"
            },
            {
                "name": "PlayStation Network",
                "date": "2011-04-19",
                "records": 77000000,
                "data_exposed": ["Email", "Password", "Name", "Address", "Payment Card"],
                "domains": ["playstation.com", "sony.com"],
                "description": "Sony PlayStation Network breach",
                "severity": "high",
                "source": "Public disclosure"
            },
        ]

    def search_by_email(self, email: str) -> List[Dict]:
        """Search breaches by email address

        Args:
            email: Email address to check

        Returns:
            List of breaches where this email domain was affected
        """
        email = email.lower().strip()

        if '@' not in email:
            return []

        domain = email.split('@')[1]

        results = []
        for breach in self.breaches:
            # Check if domain matches breach (exclude wildcard matches)
            if domain in breach['domains']:
                results.append(breach)

        return results

    def search_by_domain(self, domain: str) -> List[Dict]:
        """Search breaches by domain

        Args:
            domain: Domain to check

        Returns:
            List of breaches affecting this domain
        """
        domain = domain.lower().strip()

        results = []
        for breach in self.breaches:
            # Only match specific domains (no wildcards)
            if domain in breach['domains']:
                results.append(breach)

        return results

    def search_by_username(self, username: str) -> List[Dict]:
        """Search breaches that included usernames

        Args:
            username: Username to check (returns breaches that exposed usernames)

        Returns:
            List of breaches that included username data
        """
        results = []
        for breach in self.breaches:
            if 'Username' in breach['data_exposed']:
                results.append(breach)

        return results

    def search_by_phone(self, phone: str) -> List[Dict]:
        """Search breaches that included phone numbers

        Args:
            phone: Phone number (returns breaches that exposed phones)

        Returns:
            List of breaches that included phone number data
        """
        results = []
        for breach in self.breaches:
            if 'Phone' in breach['data_exposed']:
                results.append(breach)

        return results

    def get_all_breaches(self) -> List[Dict]:
        """Get all known breaches

        Returns:
            List of all breaches in database
        """
        return self.breaches

    def get_breach_count(self) -> int:
        """Get total number of breaches in database

        Returns:
            Number of breaches
        """
        return len(self.breaches)

    def get_total_records(self) -> int:
        """Get total number of records across all breaches

        Returns:
            Total records compromised
        """
        return sum(breach['records'] for breach in self.breaches)
