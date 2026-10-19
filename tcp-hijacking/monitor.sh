#!/usr/bin/env bash

INTERFACE=$(ip route | awk '/default/ {print $5}')

while getopts "i:" opt; do
    case "${opt}" in
        i) INTERFACE=$OPTARG ;;
        *) echo "Usage: $0 -i <network_interface>"; exit 1 ;;
    esac
done

echo "[*] Monitoring $INTERFACE for TCP anomalies..."
tshark -i $INTERFACE -Y "tcp.analysis.out_of_order or tcp.analysis.duplicate_ack" -T fields \
    -e ip.src -e ip.dst -e tcp.stream -e frame.time


