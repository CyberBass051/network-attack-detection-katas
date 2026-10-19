#!/usr/bin/env bash

if [[ "$EUID" -ne 0 ]]; then
    echo "[-] Please run this script as root"
    exit 1
fi

# Auto-detect default interface
INTERFACE=$(ip route | awk '/default/ {print $5}')

while getopts "i:" opt; do
    case ${opt} in
        i) INTERFACE=$OPTARG ;;
        *) echo "Usage: $0 -i <interface_name>"; exit 1 ;;
    esac
done

# Validate Interface
if [[ ! -d "/sys/class/net/${INTERFACE}" ]]; then
    echo "[-] Interface '$INTERFACE' not found"
    exit 1
fi

declare -a suspect_ips=()

THRESHOLD=10

echo "[*] Monitoring for RST Attacks started at: $(date)"
echo "[*] Monitoring interface $INTERFACE"
echo "------------------------------------------------------------------"
while read -r line; do
    # Extract source IP from the tcpdump line
    ip=$(echo $line | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    
    [[ -z "$ip" ]] && continue
    suspect_ips+=("$ip")
    
    # Generate frequency table of suspect IPs
    results=$(echo "${suspect_ips[@]}" | tr ' ' '\n' | sort | uniq -c | sort -nr)
    
    # Alert if count is over acceptable threshold
    while read -r count ip; do
        [[ -z "$count" ]] && continue
        if (( count > THRESHOLD )); then
            logger -p security.warn "[!] ALERT: Suspect IP $suspect_ip has sent $count RST packets!"
            echo -e "\a[!] ALERT: Suspect IP $ip has sent $count RST packet" | sudo wall
        fi
    done <<< "$results"

done< <(sudo tcpdump -nn -i "$INTERFACE" 'tcp[tcpflags] & tcp-rst != 0')



      
