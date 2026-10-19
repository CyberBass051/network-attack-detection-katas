# Network Attack & Detection Katas

Hands-on exercises pairing a network-layer attack with the detection logic that catches it — TCP, ARP and DNS. Built to understand each technique well enough to both execute and defend against it.

> ⚠️ **Educational use only.** Every script here runs against lab interfaces and RFC 5737 / private-range addresses. Only ever point these at infrastructure you own or are explicitly authorized to test.

## Why attack + detect pairs

Most portfolios show one side. Building the detector forces you to actually understand the attack's network fingerprint — what a SYN flood looks like on the wire, not just how to launch one.

## Katas

| Technique | Attack | Detection |
|---|---|---|
| TCP SYN Flood | [`tcp-syn-flood/attack.py`](tcp-syn-flood/attack.py) — spoofed-source SYN flood via Scapy | [`tcp-syn-flood/detect.sh`](tcp-syn-flood/detect.sh) — tcpdump-based SYN-without-ACK rate monitor |
| TCP RST Injection | [`tcp-rst-injection/attack.py`](tcp-rst-injection/attack.py) — sniffs a target stream and injects forged RSTs | [`tcp-rst-injection/detect.sh`](tcp-rst-injection/detect.sh) — flags source IPs sending abnormal RST volumes |
| TCP Session Hijacking | [`tcp-hijacking/attack.py`](tcp-hijacking/attack.py) — desyncs a victim session for injection | [`tcp-hijacking/monitor.sh`](tcp-hijacking/monitor.sh) — tshark filter for out-of-order / duplicate-ACK anomalies |
| ARP Spoofing | [`arp-spoofing/attack.py`](arp-spoofing/attack.py) — gateway/victim ARP cache poisoning with clean restore on exit | [`arp-spoofing/detect-linux.sh`](arp-spoofing/detect-linux.sh) · [`arp-spoofing/detect-windows.ps1`](arp-spoofing/detect-windows.ps1) — baseline gateway MAC, alert on mismatch |
| DNS Spoofing | [`dns-spoofing/attack.py`](dns-spoofing/attack.py) — forged DNS response injection for a lab domain | [`dns-spoofing/detect.sh`](dns-spoofing/detect.sh) — flags DNS responses from unexpected source IPs |

## Lab setup

All scripts assume a local test network (Scapy, tcpdump/tshark, root/admin privileges). Tested on \<your lab setup here — e.g. isolated VirtualBox host-only network\>.

## Notes

The `tcp-hijacking` and `arp-spoofing` detectors are the most directly transferable to production: the baseline-and-alert-on-deviation pattern they use is the same one behind tools like Wazuh's FIM and most IDS gateway-spoofing rules.
