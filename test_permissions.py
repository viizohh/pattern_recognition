#!/usr/bin/env python3
"""Quick diagnostic to test if packet capture works"""

import sys
import os

print("=" * 60)
print("net-watch Packet Capture Diagnostic")
print("=" * 60)
print()

# Check if running as root
if os.geteuid() != 0:
    print("✗ NOT running as root/sudo")
    print()
    print("On macOS, you MUST use sudo:")
    print("  sudo net-watch live --iface en0")
    print()
    sys.exit(1)
else:
    print("✓ Running as root")

# Test scapy import
try:
    from scapy.all import sniff
    print("✓ Scapy imported successfully")
except ImportError as e:
    print(f"✗ Cannot import scapy: {e}")
    sys.exit(1)

# Test BPF device access
try:
    fd = os.open("/dev/bpf0", os.O_RDWR)
    os.close(fd)
    print("✓ Can access /dev/bpf0")
except PermissionError:
    print("✗ Cannot access /dev/bpf0 (even with sudo)")
    print("  This is unusual - check macOS security settings")
except FileNotFoundError:
    print("! /dev/bpf0 not found, but this is OK (scapy will find another)")

# Test actual packet capture
print()
print("Testing packet capture on en0...")
print("Capturing 3 packets (browse the web now)...\n")

packet_count = 0

def count_packet(pkt):
    global packet_count
    packet_count += 1
    print(f"  ✓ Packet {packet_count}: {pkt.summary()[:60]}")

try:
    sniff(iface='en0', prn=count_packet, count=3, timeout=10, store=False)
    print()
    if packet_count > 0:
        print(f"✓ SUCCESS! Captured {packet_count} packets")
        print()
        print("net-watch should work. Try:")
        print("  sudo net-watch live --iface en0")
    else:
        print("✗ No packets captured in 10 seconds")
        print("  - Is en0 the right interface?")
        print("  - Try: ifconfig to see active interfaces")
        print("  - Or try: sudo net-watch live --iface pktap0")
except Exception as e:
    print(f"\n✗ Error during capture: {e}")
    import traceback
    traceback.print_exc()

print("=" * 60)
