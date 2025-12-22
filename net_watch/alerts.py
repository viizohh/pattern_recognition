"""Alert system for formatting and displaying security findings"""

from enum import Enum
from typing import Optional
from colorama import Fore, Style, init
from net_watch.utils import format_timestamp

# Initialize colorama
init(autoreset=True)


class AlertLevel(Enum):
    """Alert severity levels"""
    INFO = "INFO"
    WARNING = "WARNING"
    ALERT = "ALERT"
    CRITICAL = "CRITICAL"


class Alert:
    """Represents a security alert or finding"""

    def __init__(
        self,
        level: AlertLevel,
        message: str,
        explanation: Optional[str] = None,
        technical_details: Optional[str] = None,
        timestamp: Optional[float] = None
    ):
        self.level = level
        self.message = message
        self.explanation = explanation
        self.technical_details = technical_details
        self.timestamp = timestamp

    def format(self, verbose: bool = False) -> str:
        """Format the alert for display"""
        # Color based on severity
        color_map = {
            AlertLevel.INFO: Fore.CYAN,
            AlertLevel.WARNING: Fore.YELLOW,
            AlertLevel.ALERT: Fore.RED,
            AlertLevel.CRITICAL: Fore.RED + Style.BRIGHT,
        }

        color = color_map.get(self.level, Fore.WHITE)
        ts = format_timestamp(self.timestamp)

        # Build the alert string
        lines = [f"{color}[{self.level.value}] {ts}{Style.RESET_ALL}"]
        lines.append(f"{color}{self.message}{Style.RESET_ALL}")

        if self.explanation:
            lines.append(f"        → {self.explanation}")

        if verbose and self.technical_details:
            lines.append(f"\n{Fore.WHITE}Technical Details:{Style.RESET_ALL}")
            lines.append(f"  {self.technical_details}")

        return "\n".join(lines)


class AlertManager:
    """Manages and displays alerts"""

    def __init__(self, verbose: bool = False, alerts_only: bool = False):
        self.verbose = verbose
        self.alerts_only = alerts_only
        self.alerts = []

    def add_alert(self, alert: Alert):
        """Add an alert to the manager"""
        self.alerts.append(alert)
        self.display_alert(alert)

    def display_alert(self, alert: Alert):
        """Display an alert immediately"""
        # Filter based on alerts_only mode
        if self.alerts_only and alert.level == AlertLevel.INFO:
            return

        print(alert.format(verbose=self.verbose))
        print()  # Blank line for readability

    def info(self, message: str, explanation: Optional[str] = None, **kwargs):
        """Create and display an INFO alert"""
        alert = Alert(AlertLevel.INFO, message, explanation, **kwargs)
        self.add_alert(alert)

    def warning(self, message: str, explanation: Optional[str] = None, **kwargs):
        """Create and display a WARNING alert"""
        alert = Alert(AlertLevel.WARNING, message, explanation, **kwargs)
        self.add_alert(alert)

    def alert(self, message: str, explanation: Optional[str] = None, **kwargs):
        """Create and display an ALERT"""
        alert = Alert(AlertLevel.ALERT, message, explanation, **kwargs)
        self.add_alert(alert)

    def critical(self, message: str, explanation: Optional[str] = None, **kwargs):
        """Create and display a CRITICAL alert"""
        alert = Alert(AlertLevel.CRITICAL, message, explanation, **kwargs)
        self.add_alert(alert)

    def get_summary(self) -> dict:
        """Get a summary of all alerts"""
        summary = {level: 0 for level in AlertLevel}
        for alert in self.alerts:
            summary[alert.level] += 1
        return summary
