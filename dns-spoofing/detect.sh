#!/usr/bin/env bash

if [[ "$EUID" -ne 0 ]]; then
    echo "[-] Please run this script with root priviledges"
    exit 1
fi

INTERFACE=${1:? Usage: sudo $0 <network_interface>}

LEGIT_DNS_SERVER=$(ip a | grep "$INTERFACE" | awk 'NR>1 {print $2}' | cut -d'/' -f1)

echo "[*] Starting DNS spoofing detection on interface: $INTERFACE"
echo "[*] Expected Legitimate DNS Server: $LEGIT_DNS_SERVER"
echo "[*] Monitoring for unsolicited or conflicting DNS response..."
echo "--------------------------------------------------------------"

# Run tcpdump to capture UDP traffic coming from port 53 (DNS responses)
tcpdump -i "$INTERFACE" -nn "udp and src port 53" 2>/dev/null | while read -r line; do
    
    SRC_IP=$(echo $line | awk '{print $2}' | cut -d'.' -f1-4)

    if [[ -n "$SRC_IP" ]]; then
        if [[ "$SRC_IP" != "$LEGIT_DNS_SERVER" ]]; then
            echo ""
            echo "[!] ALERT: Potential DNS Spoofing Detected"
            echo "    -> Unauthorized DNS response source $SRC_IP"
            echo "-----------------------------------------------"
        fi
    fi
done
