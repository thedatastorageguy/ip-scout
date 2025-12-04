#!/usr/bin/env bash

HOSTS_FILE="/tmp/hosts_used.txt"
OPEN_FILE="/tmp/open_ips.txt"
line="----------------------------------------------------------------------------------"
set -euo pipefail

usage() {
  cat <<EOF
$line
Usage: $0 -s SUBNET -m MASK [-n COUNT]

  -s SUBNET   Network address (e.g. 172.30.200.0). Must be a valid IPv4 and last octet = 0.
  -m MASK     CIDR mask (/16–/30). Example: 16, 24, 30.
  -n COUNT    Optional. Number of open IPs to list (default: 1).

Outputs:
  $HOSTS_FILE   - hostname, MAC, IP for all hosts found by nmap
  $OPEN_FILE    - first COUNT unused IPs in the subnet (not seen by nmap)
$line
EOF
  exit 1
}

SUBNET=""
MASK=""
COUNT=1

while getopts ":s:m:n:h" opt; do
  case "$opt" in
    s) SUBNET="$OPTARG" ;;
    m) MASK="$OPTARG" ;;
    n) COUNT="$OPTARG" ;;
    h) usage ;;
    *) echo "Unknown option: -$OPTARG" >&2; usage ;;
  esac
done

# --- Validate required args ---
if [[ -z "$SUBNET" || -z "$MASK" ]]; then
  echo "ERROR: -s SUBNET and -m MASK are required." >&2
  usage
fi

# --- Validate subnet is IPv4 and last octet = 0 ---
if [[ ! "$SUBNET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo "ERROR: Subnet must be a valid IPv4 address (e.g. 172.30.200.0)." >&2
  exit 1
fi

SCAN_TMP="$(mktemp)"
USED_IPS="$(mktemp)"

IFS='.' read -r o1 o2 o3 o4 <<< "$SUBNET"

for o in "$o1" "$o2" "$o3" "$o4"; do
  if (( o < 0 || o > 255 )); then
    echo "ERROR: Subnet octet '$o' out of range (0–255)." >&2
    exit 1
  fi
done

if (( o4 != 0 )); then
  echo "ERROR: Last octet of subnet must be 0 (network address)." >&2
  exit 1
fi

# --- Validate mask ---
if [[ ! "$MASK" =~ ^[0-9]{2}$ ]]; then
  echo "ERROR: Mask must be a two-digit number (16–30)." >&2
  exit 1
fi
if (( MASK < 16 || MASK > 30 )); then
  echo "ERROR: Mask must be between 16 and 30." >&2
  exit 1
fi

# --- Validate COUNT ---
if [[ -n "${COUNT}" ]]; then
  if [[ ! "$COUNT" =~ ^[0-9]+$ ]] || (( COUNT < 1 )); then
    echo "ERROR: -n COUNT must be a positive integer." >&2
    exit 1
  fi
fi

# --- Check for nmap ---
if ! command -v nmap >/dev/null 2>&1; then
  echo "ERROR: nmap not found in PATH." >&2
  exit 1
fi

trap 'rm -f "$SCAN_TMP" "$USED_IPS" ' EXIT

# --- Convert IP <-> int helpers ---
ip2int() {
  local a b c d
  IFS='.' read -r a b c d <<< "$1"
  echo $(( (a << 24) + (b << 16) + (c << 8) + d ))
}

int2ip() {
  local ip=$1
  printf "%d.%d.%d.%d\n" \
    $(( (ip >> 24) & 255 )) \
    $(( (ip >> 16) & 255 )) \
    $(( (ip >> 8) & 255 )) \
    $(( ip & 255 ))
}

echo "Scanning $SUBNET/$MASK with nmap..."
nmap -sn --system-dns "$SUBNET/$MASK" > "$SCAN_TMP"

echo "Parsing nmap output into $HOSTS_FILE ..."

: > "$HOSTS_FILE"

# AWK: extract hostname, MAC, IP
awk -v out="$HOSTS_FILE" '
  /^Nmap scan report for / {
    host = "UNKNOWN"
    ip = ""

    # Case: Nmap scan report for host (ip)
    if (match($0, /Nmap scan report for (.+) \(([0-9.]+)\)/, m)) {
      host = m[1]
      ip   = m[2]
    }
    # Case: Nmap scan report for 172.30.x.x
    else if (match($0, /Nmap scan report for ([0-9.]+)/, m)) {
      ip = m[1]
    }

    # store state; MAC line expected next
    current_host = host
    current_ip   = ip
    mac_seen     = 0
  }

  /^MAC Address:/ {
    mac = $3
    # vendor is optional; not required by the user
    print current_host, mac, current_ip >> out
    mac_seen = 1
  }

  END {
    # If there are hosts without a MAC line, they will be missing.
    # Could be handled here if needed, but usually MAC is present for ARP/Ping scans.
  }
' "$SCAN_TMP"

# Build list of used IPs from hosts file
USED_IPS="$(mktemp)"
awk '{print $3}' "$HOSTS_FILE" | sort -u > "$USED_IPS"

echo "Collected $(wc -l < "$HOSTS_FILE") used hosts into $HOSTS_FILE"
echo "Finding first $COUNT open IP(s) in $SUBNET/$MASK ..."

# Load used IPs into associative array for fast lookup
declare -A USED
while read -r ip; do
  [[ -n "$ip" ]] && USED["$ip"]=1
done < "$USED_IPS"

# Calculate range of usable IPs in subnet
network_int=$(ip2int "$SUBNET")
total_hosts=$(( (1 << (32 - MASK)) - 2 ))   # exclude network & broadcast
start_int=$(( network_int + 1 ))
end_int=$(( network_int + total_hosts ))

: > "$OPEN_FILE"
found=0

for (( ip_int = start_int; ip_int <= end_int && found < COUNT; ip_int++ )); do
  candidate=$(int2ip "$ip_int")
  if [[ -z "${USED[$candidate]+x}" ]]; then
    echo "$candidate" | tee -a "$OPEN_FILE"
    ((found++))
  fi
done

if (( found == 0 )); then
  echo "No open IPs found in $SUBNET/$MASK (based on nmap results)."
else
  echo "Saved $found open IP(s) to $OPEN_FILE"
fi

# Cleanup temp files
rm -f "$SCAN_TMP" "$USED_IPS"
