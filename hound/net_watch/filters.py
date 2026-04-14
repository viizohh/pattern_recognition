"""Filters to reduce false positives

Network monitoring generates many alerts for normal, harmless traffic.
These filters help distinguish between suspicious activity and normal network behavior:
- mDNS/Bonjour: Apple devices discovering each other on the network
- Ephemeral ports: Temporary client-side ports used for outgoing connections
- CDN traffic: Content delivery networks with random-looking domain names
"""


def is_local_mdns_domain(domain: str) -> bool:
    """Check if domain is local mDNS/Bonjour traffic

    mDNS (Multicast DNS) is used by Apple devices and others for local network
    discovery. Domains ending in .local are NOT on the internet - they're local
    network services like printers, AirPlay devices, etc.

    Example: "Johns-MacBook-Pro.local" or "_airplay._tcp.local"

    Returns True if this is local network traffic that should be ignored
    """
    if not domain:
        return False

    # .local domains are mDNS (Apple Bonjour, etc.) - NOT internet domains
    if domain.endswith('.local'):
        return True

    # Common local service discovery patterns
    # These are used by devices to find printers, AirPlay devices, etc.
    local_patterns = [
        '_airplay._tcp',        # Apple AirPlay streaming
        '_companion-link._tcp', # Apple device pairing
        '_raop._tcp',           # Remote Audio Output Protocol
        '_printer._tcp',        # Network printers
        '_sftp-ssh._tcp',       # SSH file transfer
        '_homekit._tcp',        # Apple HomeKit devices
        '_device-info._tcp',    # Device information
        '_apple-mobdev2._tcp',  # Apple mobile device sync
    ]

    return any(pattern in domain for pattern in local_patterns)


def is_ephemeral_port(port: int) -> bool:
    """Check if port is an ephemeral (temporary client) port

    When your computer connects to a server, it uses a temporary "ephemeral" port
    on your side. These high-numbered ports (49152-65535) are normal and NOT
    suspicious, even though they look random.

    Example: Your browser connecting to google.com:443 from your port 52341
    - Port 443 (server side): HTTPS (normal)
    - Port 52341 (your side): Ephemeral port (normal, ignore)

    Returns True if this is a normal client-side port that should be ignored
    """
    # IANA standard ephemeral port range: 49152-65535
    return port >= 49152


def is_well_known_cdn(ip: str) -> bool:
    """Check if IP belongs to a well-known CDN (Content Delivery Network)

    CDNs deliver website content from servers close to you. It's normal for
    websites to load resources from CDN IP addresses.

    Note: This is a simplified check using IP prefixes. Production systems
    would use complete IP range databases or ASN (Autonomous System Number) lookups.

    Returns True if this IP is from a known CDN (normal traffic, ignore)
    """
    # Fastly CDN ranges (simplified check)
    if ip.startswith('151.101.'):
        return True

    # Cloudflare CDN
    if ip.startswith('104.'):
        return True

    # Akamai CDN (partial range)
    if ip.startswith('23.'):
        return True

    return False


def should_ignore_entropy_alert(domain: str, entropy: float) -> bool:
    """Determine if high-entropy domain should be ignored

    High entropy (randomness) in domain names can indicate DGA (Domain Generation
    Algorithm) malware, but some legitimate services also use random-looking names.

    This filter prevents false positives from:
    - Local network services with device IDs (e.g., "AA-BB-CC-DD-EE-FF.local")
    - CDN subdomains with random strings (e.g., "a1b2c3d4.cloudfront.net")
    - Load balancers with generated names

    Returns True if this high-entropy domain should NOT be flagged as suspicious
    """
    # Local network services often have high entropy (random device IDs)
    if is_local_mdns_domain(domain):
        return True

    # CDN subdomains legitimately use random-looking strings for load balancing
    cdn_patterns = [
        '.cloudfront.net',  # Amazon CloudFront
        '.fastly.net',      # Fastly CDN
        '.akamaihd.net',    # Akamai CDN
        '.cdn.',            # Generic CDN indicator
    ]

    if any(pattern in domain for pattern in cdn_patterns):
        return True

    # VERY high entropy (> 5.0) is suspicious even for CDNs
    # Still alert on these to catch potential DGA malware
    if entropy > 5.0:
        return False

    return False


def get_port_description(port: int) -> str:
    """Get human-readable description of well-known ports

    Converts port numbers to service names for better readability.
    Example: 443 → "HTTPS", 22 → "SSH"

    Returns service name if known, otherwise "Port {number}"
    """
    well_known_ports = {
        20: "FTP Data",
        21: "FTP Control",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        465: "SMTPS",
        587: "SMTP Submission",
        993: "IMAPS",
        995: "POP3S",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP Proxy",
        8443: "HTTPS Alt",
    }

    return well_known_ports.get(port, f"Port {port}")
