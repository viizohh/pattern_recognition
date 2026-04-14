# Technical Report: `sniff live --iface` Command

## Executive Summary

The `sniff live --iface` command in VCU (Network Traffic Analyzer) provides real-time network traffic monitoring and security analysis capabilities, enabling users to observe and analyze all network communications occurring on a specified network interface.

## Functionality and Implementation

### What the Command Accomplishes

The `sniff live --iface` command accomplishes comprehensive real-time network traffic monitoring by capturing, parsing, tracking, and analyzing all packets transmitted across a specified network interface. When executed with the `--show-all` flag, the tool displays detailed information about every network connection in a human-readable format, including DNS queries (revealing which domain names devices are looking up), HTTP/HTTPS connections (showing website visits and encrypted traffic destinations), TCP connections (displaying raw socket communications), and ARP broadcasts (identifying devices on the local network). Beyond simple packet capture, the command implements sophisticated behavioral analysis through three primary detection mechanisms: beaconing detection that identifies periodic automated communication patterns potentially indicative of malware command-and-control channels, tracking detection that monitors excessive third-party domain requests suggesting privacy concerns from tracking cookies or analytics scripts, and anomaly detection that flags suspicious activities such as Domain Generation Algorithm (DGA) patterns commonly used by malware, port scanning attempts, and unusual connection behaviors. The system maintains stateful tracking of all network activity, building contextual awareness by correlating DNS queries with subsequent HTTPS connections to map encrypted traffic to specific domains, tracking individual device behavior across multiple sessions, monitoring website browsing patterns including which third-party resources are loaded during site visits, and maintaining connection state information to detect patterns over time rather than analyzing packets in isolation.

### Technical Implementation

The implementation follows a sophisticated multi-layered architecture orchestrated through several specialized components working in concert. At the foundation, when a user executes `sniff live --iface en0` in the VCU interactive shell (shell.py:42-131), the command is parsed by the VCUShell class, which extracts the interface parameter and optional flags (--show-all, --verbose, --device, --alerts-only) using a custom argument parser. The shell then invokes the `run_live_capture()` function (cli.py:292-313), which initializes the complete monitoring infrastructure by instantiating a NetworkMonitor object that coordinates all analysis components. This NetworkMonitor (cli.py:25-70) creates and manages seven distinct specialized components: three protocol parsers (DNSParser for DNS traffic analysis, HTTPParser for web traffic inspection, and TCPParser for connection-level tracking), four state trackers (DeviceTracker maintaining device profiles and activity logs, DomainTracker recording domain access patterns and frequencies, ConnectionTracker monitoring TCP connection states and data volumes, and SessionTracker building contextual browsing sessions), and three behavioral detectors (BeaconingDetector identifying periodic communication patterns, TrackingDetector flagging excessive third-party tracking, and AnomalyDetector recognizing suspicious behaviors).

The actual packet capture mechanism leverages the Scapy library's `sniff()` function (capture.py:79-115), which interfaces directly with the operating system's packet capture facility (requiring elevated privileges via sudo) to access raw network packets from the specified interface. Each captured packet triggers a callback chain: the PacketCapture class's `_process_packet()` method (capture.py:52-77) first applies any device-level filtering if the --device flag was specified, then forwards the packet to all registered handlers. The primary handler, NetworkMonitor's `handle_packet()` method (cli.py:72-126), implements a comprehensive analysis pipeline that executes in sequence for every packet. In --show-all mode, the method first displays packet information by extracting layer-specific details from the Scapy packet object—for TCP packets showing source and destination IP addresses and ports (format: [TCP] 192.168.1.100:54321 → 172.217.164.110:443), for UDP packets displaying similar endpoint information, and for ARP packets showing network-level broadcasts.

Following the display step, the packet undergoes parallel analysis by all three protocol parsers, which employ deep packet inspection techniques. The DNSParser (parsers/dns.py) examines DNS layer packets, extracting query names from DNSQR records and IP addresses from DNSRR response records, calculating Shannon entropy on domain names to identify potential DGA-generated domains (high-entropy random-looking names), and maintaining bidirectional mappings between domain names and IP addresses to enable later correlation when encrypted HTTPS connections are established to those IPs. The HTTPParser (parsers/http.py) analyzes HTTP request headers to extract Host fields and request paths from plain HTTP traffic, identifies HTTPS connections by detecting TCP packets with destination port 443, and attempts to resolve the destination IP addresses to domain names using the DNS parser's cached mappings, enabling the system to display "HTTPS: example.com" rather than just raw IP addresses. The TCPParser (parsers/tcp.py) maintains state machines for each TCP connection, tracking SYN/SYN-ACK/ACK handshakes to identify new connections, monitoring data transfer volumes in both directions, detecting connection terminations via FIN or RST flags, and maintaining timestamps for temporal analysis.

The parsed data from these protocol-level analyses feeds into the tracking subsystem, where each tracker maintains sophisticated state information. The DeviceTracker (tracking/device_tracker.py) builds comprehensive profiles for each IP address observed, recording every DNS query, HTTP request, and TCP connection initiated by that device, maintaining lists of contacted domains and destination IPs, and calculating aggregate statistics like total data transferred and connection counts. The DomainTracker (tracking/domain_tracker.py) maintains per-domain statistics including query frequency, request timestamps for temporal analysis, the set of devices accessing each domain, and categorization data distinguishing first-party from third-party domains based on browsing context. The SessionTracker (tracking/session_tracker.py) implements a sliding-window algorithm to establish browsing context, determining when a user actively visits a primary website versus when third-party requests occur as part of loading that primary site, enabling output messages like "google-analytics.com (while visiting example.com)" to provide contextual awareness. The ConnectionTracker (tracking/connection_tracker.py) aggregates connection-level data, tracking which remote IPs and ports are being contacted, maintaining connection success/failure statistics, and identifying connection patterns over time.

Every ten seconds, the system executes the behavioral detection phase (cli.py:123-126), where the three detector modules analyze accumulated tracking data. The BeaconingDetector (detectors/beaconing.py) applies signal processing techniques to identify periodic patterns, calculating inter-request time intervals for each domain, computing statistical measures like mean and standard deviation of intervals, and flagging domains where requests occur at suspiciously regular intervals (e.g., every 60 seconds ± 5 seconds) which might indicate automated malware callbacks. The TrackingDetector (detectors/tracking.py) examines third-party domain activity, counting unique third-party domains contacted during a single browsing session, identifying known tracking domains through pattern matching, and generating alerts when a device contacts an excessive number of third-party trackers, potentially indicating privacy concerns. The AnomalyDetector (detectors/anomaly.py) performs multiple specialized checks: DGA detection by analyzing domain entropy and character distribution patterns, port scan detection by identifying rapid sequential connection attempts to multiple ports on the same host, and connection anomaly detection by flagging unusual protocols or suspicious connection patterns.

The entire architecture operates asynchronously with minimal performance overhead, processing packets as they arrive while maintaining persistent state, displaying real-time output when --show-all or --verbose flags are enabled, and accumulating detection data for periodic behavioral analysis. When the user terminates the capture with Ctrl+C, the system gracefully handles the interrupt signal, runs a final pass of all detectors to catch any end-of-session patterns, displays a comprehensive session summary showing all visited websites organized by device, presents aggregate statistics including total packets captured and unique domains accessed, and cleanly releases all system resources. This multi-tiered architecture—combining low-level packet capture, protocol-aware parsing, stateful tracking, and behavioral pattern detection—enables VCU to transform raw network packets into actionable security intelligence, providing both real-time visibility into network activity and sophisticated analysis capabilities that can identify security threats, privacy concerns, and anomalous behaviors that would be invisible in traditional packet capture tools.

## Command Options and Use Cases

### Basic Usage
```bash
sniff live --iface en0
```
Captures traffic on interface en0, showing only alerts and warnings.

### Show All Traffic
```bash
sniff live --iface en0 --show-all
```
Displays every packet in real-time (similar to Wireshark).

### Verbose Mode
```bash
sniff live --iface en0 --verbose
```
Shows detailed contextual information about each connection.

### Device Filtering
```bash
sniff live --iface en0 --device 192.168.1.100 --show-all
```
Monitors only traffic from/to a specific IP address.

### Alerts Only
```bash
sniff live --iface en0 --alerts-only
```
Suppresses normal output, showing only security alerts and warnings.

## Technical Requirements

- **Operating System**: macOS, Linux, or Windows
- **Privileges**: Root/sudo access (required for raw packet capture)
- **Dependencies**:
  - Scapy >= 2.5.0 (packet capture and dissection)
  - Click >= 8.1.0 (command-line interface)
  - Colorama >= 0.4.6 (colored terminal output)
  - Tabulate >= 0.9.0 (formatted output)
  - Python-dateutil >= 2.8.2 (timestamp handling)

## Code Architecture

### Component Hierarchy
```
VCUShell (shell.py)
    ↓
run_live_capture() (cli.py)
    ↓
NetworkMonitor (cli.py)
    ├── AlertManager (alerts.py)
    ├── Protocol Parsers
    │   ├── DNSParser (parsers/dns.py)
    │   ├── HTTPParser (parsers/http.py)
    │   └── TCPParser (parsers/tcp.py)
    ├── State Trackers
    │   ├── DeviceTracker (tracking/device_tracker.py)
    │   ├── DomainTracker (tracking/domain_tracker.py)
    │   ├── ConnectionTracker (tracking/connection_tracker.py)
    │   └── SessionTracker (tracking/session_tracker.py)
    └── Behavioral Detectors
        ├── BeaconingDetector (detectors/beaconing.py)
        ├── TrackingDetector (detectors/tracking.py)
        └── AnomalyDetector (detectors/anomaly.py)
    ↓
PacketCapture (capture.py)
    ↓
Scapy sniff() → Raw packets from network interface
```

### Data Flow
```
Network Interface (en0)
    ↓ [Raw packets]
Scapy sniff()
    ↓ [Packet objects]
PacketCapture._process_packet()
    ↓ [Filtered packets]
NetworkMonitor.handle_packet()
    ├→ Display (if --show-all)
    ├→ DNSParser.parse_packet() → DNS data
    ├→ HTTPParser.parse_packet() → HTTP data
    └→ TCPParser.parse_packet() → TCP data
    ↓ [Parsed data]
State Trackers (update state)
    ├→ DeviceTracker
    ├→ DomainTracker
    ├→ ConnectionTracker
    └→ SessionTracker
    ↓ [Every 10 seconds]
Behavioral Detectors (analyze patterns)
    ├→ BeaconingDetector
    ├→ TrackingDetector
    └→ AnomalyDetector
    ↓ [Alerts]
AlertManager (display warnings)
```

## Security and Privacy Considerations

The `sniff live --iface` command requires elevated privileges because it accesses raw network packets at the operating system level. This capability should be used responsibly:

- **Authorized Use Only**: Only monitor networks you own or have explicit permission to monitor
- **Privacy**: Packet capture can reveal sensitive information; handle captured data appropriately
- **Legal Compliance**: Ensure compliance with local laws regarding network monitoring
- **Ethical Guidelines**: Use for defensive security, network troubleshooting, and authorized testing only

## Performance Characteristics

- **Packet Processing Rate**: Capable of handling thousands of packets per second
- **Memory Usage**: Grows linearly with number of unique connections and domains
- **CPU Usage**: Minimal overhead; most intensive operations run every 10 seconds
- **Storage**: No persistent storage; all data held in memory during capture session

## Conclusion

The `sniff live --iface` command represents a sophisticated network monitoring solution that combines real-time packet capture with intelligent analysis. By leveraging Scapy for low-level packet access and implementing custom parsers, trackers, and detectors, VCU transforms raw network data into actionable security intelligence. The modular architecture ensures extensibility, while the layered analysis approach provides both immediate visibility and long-term pattern detection capabilities, making it a valuable tool for network security analysis, troubleshooting, and research.
