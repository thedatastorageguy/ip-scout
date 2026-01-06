#!/usr/bin/env bash

HOSTS_FILE="/tmp/hosts_used.txt"
OPEN_FILE="/tmp/open_ips.txt"
line="----------------------------------------------------------------------------------"
SUBNET=""
MASK=""
COUNT=1
VERBOSE=0
hostname=$(/bin/hostname|/bin/cut -d. -f1|/usr/bin/tr "[:upper:]" "[:lower:]")

#set -euo pipefail

usage() {
  cat <<EOF
$line
Usage: $0 -n NETWORK -m MASK [-c COUNT] [-v]

  -n NETWORK  Network address (e.g. 172.30.200.0)
              (i.e. Must be a valid IPv4 and last octet must = 0)

  -m MASK     Classless Interdomain Routing (CIDR) 'slash notation' mask 
		/8  (Class A Default): 255.0.0.0 (255, 0, 0, 0)
		/16 (Class B Default): 255.255.0.0 (255, 255, 0, 0)
		/24 (Class C Default): 255.255.255.0 (255, 255, 255, 0)
		/25: 255.255.255.128 (128 hosts)
		/26: 255.255.255.192 (64 hosts)
		/27: 255.255.255.224 (32 hosts)
		/28: 255.255.255.240 (16 hosts)
		/29: 255.255.255.248 (8 hosts)
		/30: 255.255.255.252 (4 addresses, 2 usable hosts)

  -c COUNT   [Optional] Number of open IPs to list (default: 1).

  -v          Verbose

Results:
  $HOSTS_FILE     - hostname, MAC, IP for all hosts found by nmap
  $OPEN_FILE       - first COUNT unused IPs in the subnet (not seen by nmap)
$line
EOF
  exit 1
}


log_msg() {

	local arg="$1"
	local opt="$2"
    local notime=0
	local nl=0
	local cmd="echo"

	if [ -z "$opt" ]; then
		opt="[OK]"
	elif [ $opt == "nr" ]; then
		opt="[OK]"
		cmd="printf"
	elif [ $opt == "err" ]; then
		opt="[ERROR]"
	elif [ $opt == "err2" ]; then
		opt="[ERROR]"
		notime=1
	elif [ $opt == "warn" ]; then
		opt="[WARN]"
	elif [ $opt == "verbose" ]; then
		opt="[VERBOSE]"
	fi

	if [ $notime -eq 0 ]; then
		$cmd  "[$(date '+%Y-%m-%d %H:%M:%S')] $hostname $opt $1" 
	else
		$cmd  "$hostname $opt $1" 
	fi
}

spinner() {
	PID=$1
	if [ ! -z $PID ]; then
		if [  $(ps -p $PID |grep -v TTY |wc -l) -gt  0 ]; then
			i=1
			sp="/-\|"
			echo -n ' '
			while  [ $(ps -p $PID |grep -v TTY |wc -l) -gt  0 ]; do
					printf "\b${sp:i++%${#sp}:1}"
					sleep 1
			done
		fi
	fi
}


vlog_msg() {
    if [ $VERBOSE -eq 1 ]; then
		log_msg "$1" verbose $2
	fi
}

is_number() {
    n="$1"
    if [ "$n" == 0 ]; then
        echo "0"
    elif ((n)) 2>/dev/null; then
        n=$((n))
        echo "0"
    else
        echo "1"
    fi
}
start_timer() {
  TIMER_START=$(date +%s)
}

stop_timer() {
  TIMER_END=$(date +%s)
  ELAPSED=$((TIMER_END - TIMER_START))
}

format_elapsed() {
  local t=$1
  printf "%02d:%02d:%02d" $((t/3600)) $(((t%3600)/60)) $((t%60))
}

# Main

while getopts ":n:m:c:hv" opt; do
  case "$opt" in
    v) VERBOSE=1;;
    n) SUBNET="$OPTARG" ;;
    m) MASK="$(echo $OPTARG|sed 's:/::g')" ;;
    c)  if [ $(is_number "$OPTARG") -eq 0 ]; then
		   COUNT="$OPTARG" 
		else
			log_msg "Count must be numeric" err2
			exit 1
		fi
		;;
    h) usage ;;
    *) log_msg "Unknown option: -$OPTARG" err2
		usage ;;
  esac
done

# --- Validate required args ---
if [[ -z "$SUBNET" || -z "$MASK" ]]; then
  log_msg "-n NETWORK and -m MASK are required." err2
  usage
fi

# --- Validate subnet is IPv4 and last octet = 0 ---
if [[ ! "$SUBNET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  log_msg "Subnet must be a valid IPv4 address (e.g. 172.30.200.0)." err
  exit 1
fi

SCAN_TMP="$(mktemp)"
USED_IPS="$(mktemp)"

IFS='.' read -r o1 o2 o3 o4 <<< "$SUBNET"
c=1
for o in "$o1" "$o2" "$o3" "$o4"; do
  if (( o < 0 || o > 255 )); then
    log_msg "Subnet octet#$c = '$o' and is out of range (0–255)." err
    exit 1
  else
	vlog_msg "Subnet octet#$c = $o"
  fi
  ((c++))
done

if (( o4 != 0 )); then
  log_msg "Last octet [$o4] of subnet must be 0 (network address)."  err
  exit 1
	
fi

# --- Validate mask ---
if [[ ! "$MASK" =~ ^[0-9]{2}$ ]]; then
  log_msg "Mask [$MASK] must be a two-digit number (8-30)." err
  exit 1
fi
if (( MASK < 8 || MASK > 30 )); then
  log_msg "Mask must be between 9 and 30."  err
  exit 1
fi

# --- Validate COUNT ---
if [[ -n "${COUNT}" ]]; then
  if [[ ! "$COUNT" =~ ^[0-9]+$ ]] || (( COUNT < 1 )); then
    log_msg "-n COUNT must be a positive integer." err
    exit 1
  fi
fi

# --- Check for nmap ---
if ! command -v nmap >/dev/null 2>&1; then
  log_msg "nmap not found in PATH. " err
  log_msg "Please install nmap. (ex dnf -y install nmap)" err
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

start_timer
vlog_msg "[COMMAND] nmap -sn --system-dns $SUBNET/$MASK"

if [ $VERBOSE -eq 0 ]; then
	log_msg "Scanning $SUBNET/$MASK with nmap:  " nr
	nmap -sn --system-dns "$SUBNET/$MASK" &> "$SCAN_TMP" 2>&1 & 
	spinner $!
    printf "\n"
else
	log_msg "Scanning $SUBNET/$MASK with nmap" 
	nmap -sn --system-dns "$SUBNET/$MASK" 2>/dev/null |tee -a  "$SCAN_TMP"
fi
sleep 10
stop_timer
log_msg "nmap scan completed in $(format_elapsed  $ELAPSED) "

log_msg "Parsing nmap output into $HOSTS_FILE ..."

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

log_msg "Collected $(wc -l < "$HOSTS_FILE") used hosts into $HOSTS_FILE"
log_msg "Finding first $COUNT open IP(s) in $SUBNET/$MASK ..."

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
  log_msg "No open IPs found in $SUBNET/$MASK (based on nmap results)." err
else
  log_msg "Saved $found open IP(s) to $OPEN_FILE"
fi

# Cleanup temp files
rm -f "$SCAN_TMP" "$USED_IPS"
