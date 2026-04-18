"""Packet capture engine for live and pcap analysis

This module handles the low-level packet capture using Scapy:
- Live capture: Sniffs packets in real-time from a network interface
- PCAP analysis: Reads and analyzes previously captured packet files
- Filtering: Can filter to show only specific device's traffic
"""

import time
from typing import Callable, Optional
from scapy.all import sniff, rdpcap, IP, TCP, UDP, DNS, Raw
from scapy.layers.http import HTTPRequest, HTTPResponse
from net_watch.alerts import AlertManager


class PacketCapture:
    """Handles packet capture from live interfaces or pcap files

    This is the core packet capture engine. It uses Scapy to capture packets
    and passes them to registered handlers (like NetworkMonitor) for analysis.

    Two modes:
    1. Live capture: Captures packets in real-time from a network interface (requires sudo)
    2. PCAP analysis: Reads packets from a saved .pcap file
    """

    def __init__(
        self,
        alert_manager: AlertManager,
        interface: Optional[str] = None,
        pcap_file: Optional[str] = None,
        filter_device: Optional[str] = None,
        summary_callback: Optional[Callable] = None,
        packet_limit: Optional[int] = None
    ):
        self.alert_manager = alert_manager
        self.interface = interface
        self.pcap_file = pcap_file
        self.filter_device = filter_device
        self.packet_count = 0
        self.packet_limit = packet_limit
        self.start_time = None
        self.handlers = []
        self.summary_callback = summary_callback

    def register_handler(self, handler: Callable):
        """Register a packet handler callback

        Handlers are functions that get called for each packet.
        Example: NetworkMonitor.handle_packet
        """
        self.handlers.append(handler)

    def _process_packet(self, packet):
        """Process a single packet

        This is called by Scapy for every packet captured. It:
        1. Filters by device IP if requested
        2. Calls all registered handlers to analyze the packet
        """
        self.packet_count += 1

        # If filtering by device, only process packets involving that device
        if self.filter_device:
            if not packet.haslayer(IP):
                return  # Skip non-IP packets (like ARP)
            ip_layer = packet[IP]
            if ip_layer.src != self.filter_device and ip_layer.dst != self.filter_device:
                return

        # Pass packet to all registered handlers for analysis
        for handler in self.handlers:
            try:
                handler(packet)
            except Exception as e:
                # Don't crash the capture if a handler fails
                if self.alert_manager.verbose:
                    print(f"Handler error: {e}")

    def start_live_capture(self):
        """Start live packet capture from a network interface

        Uses Scapy to capture packets in real-time from the specified interface.
        Requires root/sudo privileges to access the network interface.

        The capture runs until the user presses Ctrl+C, then shows a summary.
        """
        self.start_time = time.time()

        print(f"Starting live capture on {self.interface}...")
        if self.filter_device:
            print(f"Filtering for device: {self.filter_device}")
        if self.packet_limit:
            print(f"Will capture {self.packet_limit} packets\n")
        else:
            print("Press Ctrl+C to stop\n")

        try:
            # Use Scapy's sniff() function to capture packets
            # Note: Don't use BPF filters on macOS - filter in Python instead
            # (BPF compilation fails on some macOS configurations with libpcap)
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                count=self.packet_limit if self.packet_limit else 0
            )
            if self.packet_limit:
                self._show_summary()
        except KeyboardInterrupt:
            # User pressed Ctrl+C - show summary and exit gracefully
            self._show_summary()
        except PermissionError:
            # Packet capture requires root privileges
            print("\nError: Packet capture requires root/administrator privileges.")
            print("Try running with sudo: sudo hound")
        except Exception as e:
            # Other errors (interface not found, etc.)
            print(f"\nCapture error: {e}")

    def analyze_pcap(self):
        """Analyze a pcap file"""
        self.start_time = time.time()

        print(f"Analyzing pcap file: {self.pcap_file}...")
        if self.filter_device:
            print(f"Filtering for device: {self.filter_device}")
        print()

        try:
            packets = rdpcap(self.pcap_file)
            print(f"Loaded {len(packets)} packets\n")

            for packet in packets:
                self._process_packet(packet)

            self._show_summary()

        except FileNotFoundError:
            print(f"\nError: File not found: {self.pcap_file}")
        except Exception as e:
            print(f"\nError reading pcap: {e}")

    def _build_bpf_filter(self) -> Optional[str]:
        """Build a BPF filter string"""
        # Focus on TCP/UDP traffic (DNS, HTTP, HTTPS, etc.)
        filters = []

        # If filtering by device, add that
        if self.filter_device:
            filters.append(f"host {self.filter_device}")

        # Combine filters
        if filters:
            return " and ".join(filters)

        return None

    def _show_summary(self):
        """Show capture summary"""
        if self.summary_callback:
            self.summary_callback()

        if self.start_time:
            duration = time.time() - self.start_time
            print("\n" + "=" * 60)
            print(f"Capture Summary:")
            print(f"  Packets processed: {self.packet_count}")
            print(f"  Duration: {duration:.1f} seconds")
            print(f"  Rate: {self.packet_count/duration:.1f} packets/sec")

            alert_summary = self.alert_manager.get_summary()
            print(f"\nAlerts:")
            for level, count in alert_summary.items():
                if count > 0:
                    print(f"  {level.value}: {count}")
            print("=" * 60)
