"""Utility functions for net-watch"""

import time
from datetime import datetime
from typing import Optional


def format_timestamp(ts: Optional[float] = None) -> str:
    """Format a timestamp into human-readable format"""
    if ts is None:
        ts = time.time()
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def format_duration(seconds: float) -> str:
    """Format a duration in seconds into human-readable format"""
    if seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    else:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''}"


def format_bytes(num_bytes: int) -> str:
    """Format bytes into human-readable format"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} TB"


def is_private_ip(ip: str) -> bool:
    """Check if an IP address is private/internal"""
    try:
        parts = [int(p) for p in ip.split('.')]
        if len(parts) != 4:
            return False

        # 10.0.0.0/8
        if parts[0] == 10:
            return True
        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True
        # Loopback
        if parts[0] == 127:
            return True

        return False
    except (ValueError, AttributeError):
        return False


def calculate_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string"""
    import math
    from collections import Counter

    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)
    entropy = 0.0

    for count in counter.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy
