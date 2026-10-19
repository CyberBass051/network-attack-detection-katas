#!/usr/bin/env bash

if [[ "$EUID" -ne 0 ]]; then
    echo "[-] Please run this script as root."
    exit 1
fi

INTERFACE=$(ip route | awk '/default/ {print $5}')
THRESHOLD=100

while getopts "i:t:" opt; do
    case ${opt} in
        i) INTERFACE=$OPTARG ;;
        t) THRESHOLD=$OPTARG ;;
        *) echo "Usage: $0 -i <interface_name> -t <packet_threshold>" ; exit 1 ;;
    esac
done

echo "[*] Starting TCP packets per second monitoring"
echo "[*] Interface: $INTERFACE"
echo "[*] Monitoring for possible TCP SYN Flood attack"
echo "-------------------------------------------------"

while true; do
    SYN_COUNT=$(tcpdump -i $INTERFACE -c $THRESHOLD 'tcp[tcpflags] & (tcp-syn) != 0 and tcp[tcpflags] & (tcp-ack) == 0' 2>/dev/null)

    if [[ "$SYN_COUNT" -ge "$THRESHOLD" ]]; then
        echo "[!] $(date) - ALERT: Possible SYN Flood! Detected high volume on $INTERFACE"
    fi
    sleep 1
done