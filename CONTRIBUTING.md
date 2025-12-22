# Contributing to net-watch

Thank you for your interest in contributing to net-watch! This document provides guidelines and information for contributors.

## Areas for Contribution

### 1. Protocol Parsers
Add support for additional protocols:
- **TLS/SSL**: Fingerprinting, certificate analysis
- **DHCP**: Device identification
- **SMTP/IMAP**: Email traffic analysis
- **SSH**: Connection monitoring
- **FTP**: File transfer detection
- **SMB**: Windows network traffic

**Location**: `net_watch/parsers/`

### 2. Behavior Detectors
Implement new detection algorithms:
- **Data exfiltration**: Large uploads to unknown destinations
- **Lateral movement**: Internal scanning and pivoting
- **Credential stuffing**: Repeated login attempts
- **Cryptomining**: Detection of mining pool connections
- **Tunneling**: DNS tunneling, ICMP tunneling detection

**Location**: `net_watch/detectors/`

### 3. Tracking & Analytics
Enhance tracking capabilities:
- Machine learning for baseline behavior
- Time-series analysis for trends
- Geographic IP analysis
- ASN (Autonomous System) tracking
- Certificate authority tracking

**Location**: `net_watch/tracking/`

### 4. Output & Reporting
Improve user experience:
- JSON export for integration
- CSV export for analysis
- HTML reports
- Real-time web dashboard
- Prometheus metrics export
- Syslog integration

**Location**: `net_watch/alerts.py`, new `net_watch/export/` module

### 5. Performance Optimization
- Async packet processing
- Multi-threaded analysis
- Packet filtering optimization
- Memory usage reduction
- Database backend for long-term storage

### 6. Platform Support
- Windows compatibility improvements
- macOS System Integrity Protection workarounds
- BSD support
- Docker containerization

## Development Setup

### 1. Clone and Install
```bash
git clone <repository>
cd net-watch
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install -e .
```

### 2. Development Dependencies
```bash
pip install pytest pytest-cov black flake8 mypy
```

### 3. Running Tests
```bash
# Run all tests
pytest

# With coverage
pytest --cov=net_watch

# Specific test file
pytest tests/test_parsers.py
```

## Code Style

### Python Style Guide
- Follow PEP 8
- Use type hints
- Maximum line length: 100 characters
- Use descriptive variable names

### Formatting
```bash
# Format code with black
black net_watch/

# Check style with flake8
flake8 net_watch/

# Type checking with mypy
mypy net_watch/
```

### Documentation
- Docstrings for all classes and functions
- Use Google-style docstrings
- Include type information

Example:
```python
def parse_packet(self, packet) -> Optional[dict]:
    """
    Parse a DNS packet and extract relevant information.

    Args:
        packet: Scapy packet object to parse

    Returns:
        Dictionary containing parsed data or None if not a DNS packet

    Example:
        >>> parser = DNSParser()
        >>> result = parser.parse_packet(dns_packet)
        >>> print(result['domain'])
        'example.com'
    """
    pass
```

## Adding a New Protocol Parser

### 1. Create Parser File
Create `net_watch/parsers/your_protocol.py`:

```python
"""Your protocol parser"""

import time
from typing import Dict, Optional
from scapy.all import YourProtocolLayer


class YourProtocolParser:
    """Parses Your Protocol traffic"""

    def __init__(self):
        self.stats = {}

    def parse_packet(self, packet) -> Optional[dict]:
        """Parse a packet for this protocol"""
        if not packet.haslayer(YourProtocolLayer):
            return None

        # Extract relevant data
        data = {
            "type": "your_protocol",
            "timestamp": time.time(),
            # ... other fields
        }

        return data
```

### 2. Integrate with CLI
Add to `net_watch/cli.py`:

```python
from net_watch.parsers.your_protocol import YourProtocolParser

class NetworkMonitor:
    def __init__(self, ...):
        # Add your parser
        self.your_protocol_parser = YourProtocolParser()

    def handle_packet(self, packet):
        # Parse with your parser
        your_data = self.your_protocol_parser.parse_packet(packet)

        if your_data:
            self._handle_your_protocol_data(your_data)
```

### 3. Add Tests
Create `tests/test_your_protocol.py`:

```python
import pytest
from net_watch.parsers.your_protocol import YourProtocolParser


def test_parse_packet():
    parser = YourProtocolParser()
    # Create test packet
    # Test parsing
    # Assert results
```

## Adding a New Detector

### 1. Create Detector File
Create `net_watch/detectors/your_detector.py`:

```python
"""Your detector description"""

from net_watch.alerts import AlertManager


class YourDetector:
    """Detects specific behavior"""

    def __init__(self, alert_manager: AlertManager):
        self.alert_manager = alert_manager
        self.detected_issues = set()

    def check_for_issues(self):
        """Run detection logic"""
        # Analyze data
        # Generate alerts
        if suspicious:
            self.alert_manager.alert(
                "Description of issue",
                explanation="Plain English explanation"
            )
```

### 2. Integrate with Monitor
Add to `net_watch/cli.py`:

```python
from net_watch.detectors.your_detector import YourDetector

class NetworkMonitor:
    def __init__(self, ...):
        self.your_detector = YourDetector(self.alert_manager)

    def run_detectors(self):
        # Add to detector runs
        self.your_detector.check_for_issues()
```

## Testing

### Unit Tests
Test individual components:
```python
def test_dns_parser():
    parser = DNSParser()
    # Create mock packet
    result = parser.parse_packet(packet)
    assert result['domain'] == 'example.com'
```

### Integration Tests
Test multiple components together:
```python
def test_beaconing_detection():
    monitor = NetworkMonitor()
    # Feed packets
    # Check alerts generated
```

### PCAP Tests
Use real packet captures:
```python
def test_with_real_pcap():
    packets = rdpcap('tests/fixtures/sample.pcap')
    # Process and verify
```

## Documentation

### README Updates
- Add new features to feature list
- Update examples if CLI changes
- Add troubleshooting for new issues

### Code Documentation
- Docstrings for all public functions
- Comments for complex logic
- Type hints for better IDE support

### Examples
Add examples to `examples.md` demonstrating new features.

## Submitting Changes

### 1. Create a Branch
```bash
git checkout -b feature/your-feature-name
```

### 2. Make Changes
- Write code
- Add tests
- Update documentation

### 3. Test
```bash
pytest
black net_watch/
flake8 net_watch/
```

### 4. Commit
```bash
git add .
git commit -m "Add feature: description"
```

### 5. Push and Create PR
```bash
git push origin feature/your-feature-name
# Create Pull Request on GitHub
```

## Code Review Process

1. **Automated Checks**: Tests and linting must pass
2. **Code Review**: Maintainer reviews code quality
3. **Documentation**: Ensure docs are updated
4. **Testing**: Verify functionality works as expected

## Security Considerations

### Responsible Disclosure
- Report security issues privately
- Don't publish exploits publicly
- Allow time for fixes before disclosure

### Code Security
- Avoid hardcoded credentials
- Sanitize user input
- Be careful with exec/eval
- Validate file paths

### Privacy
- Don't log sensitive data
- Anonymize examples
- Respect user privacy

## Questions?

- Open an issue for discussions
- Check existing issues and PRs
- Reach out to maintainers

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
