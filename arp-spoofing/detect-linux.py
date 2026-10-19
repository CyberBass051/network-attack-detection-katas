#!/usr/bin/env bash

if [[ "$EUID" -ne 0 ]]; then
    echo "[-] Please run this script as root"
    exit 1
fi

INTERFACE=$(ip route | awk '/default/ {print $5}')
GATEWAY_IP=$(ip route | awk '/default/ {print $3}')
usage="$0 -i <interface> -g <gateway_ip>"

while getopts "i:g:" opt; do
    case ${opt} in 
        i) INTERFACE=$OPTARG ;;
        g) GATEWAY_IP=$OPTARG ;;
        *) echo "$usage"; exit 1 ;;
    esac
done


LEGIT_MAC=$(ip neigh | awk "/$GATEWAY_IP.*REACHABLE/ {print \$5}")

echo "[*] Starting ARP Spoofing Detector on interface: $INTERFACE"
echo "[*] Monitoring Gateway IP: $GATEWAY_IP"
echo "[*] Trusted Gateway MAC: $LEGIT_MAC"
echo "[*] Listening for malicious ARP replies..."
echo "-------------------------------------------------------------"

# Use tcpdump to monitor ARP packets (specifically looking for ARP replies)
tcpdump -i "$INTERFACE" -nn 'arp[6:2] == 2' 2>/dev/null | while read -r line; do
    SENDER_IP=$(echo "$line" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -n 1)
    SENDER_MAC=$(echo "$line" | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -n 1 | tr '[:upper:]' '[:lower:]')

    if [[ "$SENDER_IP" == "$GATEWAY_IP" ]]; then
        if [[ "$SENDER_MAC" != "$LEGIT_MAC" ]]; then
            echo ""
            echo "[!] ALERT: ARP Spoofing / Poison Detected!"
            echo "    -> Gateway IP ($GATEWAY_IP) is claimed by unauthorized MAC: $SENDER_MAC"
            echo "    -> Ray Packet: $line"
            echo "-------------------------------------------------------------------------------"
        else
            echo "[+] Legitimate ARP traffic verified for gateway from: $SENDER_MAC"
        fi
    fi
done
