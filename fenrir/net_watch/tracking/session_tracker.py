"""Session tracking to correlate traffic with websites being visited

This module helps answer "why is my device connecting to this domain?"
For example, when you visit LinkedIn, it loads resources from doubleclick.net,
google-analytics.com, etc. This tracker correlates those third-party domains
with the primary website (LinkedIn) you're actually visiting.
"""

import time
from typing import Dict, List, Set, Optional
from collections import defaultdict


class BrowsingSession:
    """Represents a web browsing session for a website

    When you visit a website like "linkedin.com", that's the primary domain.
    The website then loads resources from third-party domains (ads, analytics, etc.).
    This class tracks both the primary site and all the third-party domains it loads.
    """

    def __init__(self, primary_domain: str):
        self.primary_domain = primary_domain  # The main website being visited
        self.start_time = time.time()
        self.last_activity = self.start_time
        self.third_party_domains: Set[str] = set()  # Tracking, ads, CDNs loaded from this site
        self.dns_queries: List[str] = []
        self.http_requests: List[dict] = []
        self.connection_count = 0

    def add_third_party(self, domain: str):
        """Add a third-party domain loaded from this site

        For example, when visiting linkedin.com, this tracks google-analytics.com,
        doubleclick.net, etc. as third-party domains
        """
        self.third_party_domains.add(domain)
        self.last_activity = time.time()

    def add_connection(self):
        """Track a connection made during this session"""
        self.connection_count += 1
        self.last_activity = time.time()

    def is_active(self, timeout: float = 30) -> bool:
        """Check if session is still active (had activity within timeout seconds)"""
        return (time.time() - self.last_activity) < timeout


class SessionTracker:
    """Tracks browsing sessions to provide context for traffic

    This tracker helps make network traffic human-readable by showing context like:
    - "doubleclick.net (while visiting linkedin.com)"
    - "google-analytics.com (while visiting youtube.com)"

    It distinguishes between:
    - Primary domains: Sites you directly visit (linkedin.com, youtube.com)
    - Third-party domains: Resources loaded by those sites (ads, analytics, CDNs)
    """

    def __init__(self):
        # Active browsing sessions per device
        # Each device can have multiple active sessions (multiple tabs/windows)
        self.active_sessions: Dict[str, List[BrowsingSession]] = defaultdict(list)

        # Recently visited domains for each device (for historical context)
        self.recent_visits: Dict[str, List[tuple]] = defaultdict(list)  # device -> [(domain, timestamp)]

        # Learn which domains are typically primary vs third-party
        self.known_primary_domains: Set[str] = set()      # linkedin.com, youtube.com, etc.
        self.known_third_party_domains: Set[str] = set()  # google-analytics.com, doubleclick.net, etc.

    def start_session(self, device_ip: str, primary_domain: str):
        """Start a new browsing session"""
        # Clean up old inactive sessions first
        self._cleanup_inactive_sessions(device_ip)

        session = BrowsingSession(primary_domain)
        self.active_sessions[device_ip].append(session)
        self.known_primary_domains.add(primary_domain)

        self.recent_visits[device_ip].append((primary_domain, time.time()))

        # Keep only last 20 visits
        if len(self.recent_visits[device_ip]) > 20:
            self.recent_visits[device_ip] = self.recent_visits[device_ip][-20:]

    def track_domain_access(self, device_ip: str, domain: str, is_http_request: bool = False):
        """Track when a device accesses a domain"""
        sessions = self.active_sessions.get(device_ip, [])

        if not sessions:
            # New session - this domain is primary
            self.start_session(device_ip, domain)
        else:
            if self._is_likely_primary_domain(domain):
                # New primary site being visited
                self.start_session(device_ip, domain)
            else:
                # Add to most recent session as third-party
                for session in reversed(sessions):
                    if session.is_active():
                        if domain != session.primary_domain:
                            session.add_third_party(domain)
                            self.known_third_party_domains.add(domain)
                        session.add_connection()
                        break

    def get_context_for_domain(self, device_ip: str, domain: str) -> Optional[str]:
        """Get the website context for a domain (e.g., 'while visiting linkedin.com')"""
        sessions = self.active_sessions.get(device_ip, [])

        for session in reversed(sessions):
            if session.is_active():
                if domain in session.third_party_domains:
                    return f"while visiting {session.primary_domain}"
                elif domain == session.primary_domain:
                    return f"on {session.primary_domain}"

        recent = self.recent_visits.get(device_ip, [])
        if recent:
            last_site, last_time = recent[-1]
            if time.time() - last_time < 60:  # Within last minute
                return f"recently visited {last_site}"

        return None

    def get_active_session_for_device(self, device_ip: str) -> Optional[BrowsingSession]:
        """Get the most recent active session for a device"""
        sessions = self.active_sessions.get(device_ip, [])

        for session in reversed(sessions):
            if session.is_active():
                return session

        return None

    def get_recent_websites(self, device_ip: str, limit: int = 5) -> List[str]:
        """Get recently visited websites for a device"""
        recent = self.recent_visits.get(device_ip, [])
        unique_sites = []
        seen = set()

        for domain, _ in reversed(recent):
            if domain not in seen:
                unique_sites.append(domain)
                seen.add(domain)
            if len(unique_sites) >= limit:
                break

        return unique_sites

    def _is_likely_primary_domain(self, domain: str) -> bool:
        """Determine if a domain is likely a primary site vs third-party resource"""
        # Known third-party domains
        third_party_keywords = [
            'analytics', 'tracking', 'ads', 'doubleclick', 'googlesyndication',
            'facebook.net', 'fbcdn', 'googletagmanager', 'pixel',
            'cdn', 'cloudfront', 'akamai', 'fastly'
        ]

        domain_lower = domain.lower()

        # If it matches third-party patterns, it's not primary
        if any(keyword in domain_lower for keyword in third_party_keywords):
            return False

        # If we've seen it as third-party before, it's not primary
        if domain in self.known_third_party_domains:
            return False

        # If it has a real TLD and doesn't look like a resource domain, likely primary
        real_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co']
        if any(domain.endswith(tld) for tld in real_tlds):
            return True

        return False

    def _cleanup_inactive_sessions(self, device_ip: str):
        """Remove inactive sessions to save memory"""
        sessions = self.active_sessions.get(device_ip, [])
        active = [s for s in sessions if s.is_active(timeout=300)]  # 5 minutes

        if active:
            self.active_sessions[device_ip] = active
        elif device_ip in self.active_sessions:
            del self.active_sessions[device_ip]

    def get_session_summary(self, device_ip: str) -> dict:
        """Get a summary of browsing activity for a device"""
        session = self.get_active_session_for_device(device_ip)

        if session:
            return {
                'current_site': session.primary_domain,
                'third_party_count': len(session.third_party_domains),
                'connection_count': session.connection_count,
                'duration': time.time() - session.start_time,
                'is_active': session.is_active()
            }

        return {
            'current_site': None,
            'recent_sites': self.get_recent_websites(device_ip)
        }
