#!/usr/bin/env python3
"""Simple test to verify packet capture is working"""

from scapy.all import sniff, IP, TCP, UDP, DNS
import sys

print("Testing basic packet capture for 10 seconds...")
print("Visit a website now to generate traffic!")
print()

packet_count = 0

def show_packet(pkt):
    global packet_count
    packet_count += 1

    # Show basic info about each packet
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst

        if pkt.haslayer(DNS):
            if pkt[DNS].qr == 0:  # Query
                domain = pkt[DNS].qd.qname.decode('utf-8', errors='ignore').rstrip('.')
                print(f"[DNS Query] {src} → {domain}")
        elif pkt.haslayer(TCP):
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            print(f"[TCP] {src}:{sport} → {dst}:{dport}")
        elif pkt.haslayer(UDP):
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
            print(f"[UDP] {src}:{sport} → {dst}:{dport}")
        else:
            print(f"[IP] {src} → {dst}")
    else:
        print(f"[Non-IP packet] {pkt.summary()[:60]}")

try:
    print("Capturing on en0...")
    sniff(iface='en0', prn=show_packet, timeout=10, store=False)
    print(f"\nTotal packets captured: {packet_count}")

    if packet_count == 0:
        print("\n⚠️  NO PACKETS CAPTURED!")
        print("This means:")
        print("  1. You need to run with sudo")
        print("  2. Or en0 might not be the right interface")
        print("  3. Or there's a permissions issue")
    else:
        print(f"\n✓ Packet capture is working! Got {packet_count} packets")

except PermissionError:
    print("\n✗ PERMISSION ERROR - Run with sudo:")
    print(f"  sudo python3 {sys.argv[0]}")
except Exception as e:
    print(f"\n✗ Error: {e}")
    import traceback
    traceback.print_exc()
