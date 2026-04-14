"""Tracking detection - identifies excessive third-party tracking"""

import time
from typing import Dict, Set
from collections import defaultdict
from net_watch.tracking.domain_tracker import DomainTracker
from net_watch.tracking.device_tracker import DeviceTracker
from net_watch.alerts import AlertManager


class TrackingDetector:
    """Detects excessive third-party tracking and analytics"""

    def __init__(
        self,
        domain_tracker: DomainTracker,
        device_tracker: DeviceTracker,
        alert_manager: AlertManager
    ):
        self.domain_tracker = domain_tracker
        self.device_tracker = device_tracker
        self.alert_manager = alert_manager
        self.alerted_sessions = set()
        self.session_trackers: Dict[str, Dict] = defaultdict(lambda: {
            'primary_domain': None,
            'third_party_domains': set(),
            'tracker_domains': set(),
            'start_time': time.time()
        })

        # Detection thresholds
        self.excessive_tracking_threshold = 20  # domains
        self.check_interval = 30  # seconds

    def track_web_session(self, device_ip: str, domain: str, is_primary: bool = False):
        """Track a web browsing session for tracking detection"""
        session_key = f"{device_ip}:{time.time() // 300}"  # 5-minute windows

        session = self.session_trackers[session_key]

        if is_primary:
            session['primary_domain'] = domain
        else:
            session['third_party_domains'].add(domain)

            # Check if it's a known tracker
            if self.domain_tracker.is_known_tracker(domain):
                session['tracker_domains'].add(domain)

    def check_for_excessive_tracking(self):
        """Check for excessive third-party tracking"""
        current_time = time.time()

        for session_key, session in list(self.session_trackers.items()):
            # Skip if already alerted
            if session_key in self.alerted_sessions:
                continue

            # Skip recent sessions (let them accumulate data)
            if current_time - session['start_time'] < 10:
                continue

            third_party_count = len(session['third_party_domains'])
            tracker_count = len(session['tracker_domains'])

            # Alert on excessive tracking
            if third_party_count > self.excessive_tracking_threshold:
                self._generate_excessive_tracking_alert(
                    session,
                    third_party_count,
                    tracker_count
                )
                self.alerted_sessions.add(session_key)

            # Clean up old sessions
            if current_time - session['start_time'] > 600:  # 10 minutes
                del self.session_trackers[session_key]

    def _generate_excessive_tracking_alert(
        self,
        session: dict,
        third_party_count: int,
        tracker_count: int
    ):
        """Generate alert for excessive tracking"""
        primary = session.get('primary_domain', 'a website')

        if tracker_count > 10:
            self.alert_manager.warning(
                f"Device made {third_party_count} connections to third-party domains while visiting {primary}.",
                explanation=f"Detected {tracker_count} known tracking/ad services. This is common but privacy-invasive.",
                technical_details=f"Trackers: {', '.join(list(session['tracker_domains'])[:5])}..."
            )
        else:
            self.alert_manager.info(
                f"Device made {third_party_count} connections to third-party domains while visiting {primary}.",
                explanation="Common tracking behavior, low risk."
            )

    def analyze_device_tracking_exposure(self, device_ip: str) -> dict:
        """Analyze a device's exposure to trackers"""
        device = self.device_tracker.get_or_create_device(device_ip)
        tracking_domains = []
        total_tracker_contacts = 0

        for domain in device.domains_contacted:
            if self.domain_tracker.is_known_tracker(domain):
                profile = self.domain_tracker.get_or_create_domain(domain)
                tracking_domains.append(domain)
                total_tracker_contacts += profile.query_count

        return {
            "device_ip": device_ip,
            "unique_trackers": len(tracking_domains),
            "total_tracker_contacts": total_tracker_contacts,
            "tracker_list": tracking_domains[:10],  # Top 10
            "total_domains": len(device.domains_contacted),
            "tracking_ratio": len(tracking_domains) / max(len(device.domains_contacted), 1)
        }

    def identify_tracking_heavy_domains(self, threshold: int = 5) -> list:
        """
        Identify primary domains that load many third-party trackers
        Returns list of (domain, tracker_count) tuples
        """
        heavy_trackers = []

        for domain, profile in self.domain_tracker.domains.items():
            if profile.is_third_party:
                continue  # Skip third-party domains

            # Count third-party trackers loaded from this domain
            third_party_count = self.domain_tracker.get_third_party_count_for_domain(domain)
            tracker_count = 0

            # Count how many are known trackers
            for tp_domain, tp_profile in self.domain_tracker.domains.items():
                if (tp_profile.is_third_party and
                    tp_profile.parent_domain == domain and
                    self.domain_tracker.is_known_tracker(tp_domain)):
                    tracker_count += 1

            if tracker_count >= threshold:
                heavy_trackers.append((domain, tracker_count, third_party_count))

        return sorted(heavy_trackers, key=lambda x: x[1], reverse=True)

    def get_tracker_summary(self) -> dict:
        """Get overall tracking summary"""
        all_trackers = self.domain_tracker.get_tracking_domains()

        tracker_categories = defaultdict(int)
        for tracker in all_trackers:
            base_domain = tracker.get_base_domain()

            # Categorize
            if 'google' in base_domain:
                tracker_categories['Google'] += 1
            elif 'facebook' in base_domain or 'fb' in base_domain:
                tracker_categories['Facebook'] += 1
            else:
                tracker_categories['Other'] += 1

        return {
            "total_trackers": len(all_trackers),
            "categories": dict(tracker_categories),
            "most_active": sorted(
                all_trackers,
                key=lambda x: x.query_count,
                reverse=True
            )[:5]
        }

    def detect_fingerprinting_attempts(self) -> list:
        """
        Detect potential browser fingerprinting
        (multiple requests to tracking domains in quick succession)
        """
        fingerprinting = []

        for domain, profile in self.domain_tracker.domains.items():
            if not self.domain_tracker.is_known_tracker(domain):
                continue

            # Check for burst of queries
            if len(profile.query_timestamps) < 5:
                continue

            sorted_times = sorted(profile.query_timestamps)
            recent_window = 5.0  # 5 seconds

            for i in range(len(sorted_times) - 4):
                window_queries = [
                    t for t in sorted_times[i:]
                    if t - sorted_times[i] <= recent_window
                ]

                if len(window_queries) >= 5:
                    fingerprinting.append({
                        "domain": domain,
                        "query_burst": len(window_queries),
                        "window": recent_window,
                        "timestamp": sorted_times[i]
                    })
                    break

        return fingerprinting
