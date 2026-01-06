README - ip-scout

# ip-scout

Tool to search a DHCP subnet and locate and log all used and open IP addresses

# Usage

```
# ./ip-scout.sh
[ERROR] -s SUBNET and -m MASK are required.
----------------------------------------------------------------------------------
Usage: ./ip-scout.sh -s SUBNET -m MASK [-n COUNT] [-v]

  -s SUBNET   Network address (e.g. 172.30.200.0)
              (i.e. Must be a valid IPv4 and last octet must = 0)

  -m MASK     Classless InterdomainRouting (CIDR) 'slash notation' mask
                /8  (Class A Default): 255.0.0.0 (255, 0, 0, 0)
                /16 (Class B Default): 255.255.0.0 (255, 255, 0, 0)
                /24 (Class C Default): 255.255.255.0 (255, 255, 255, 0)
                /25: 255.255.255.128 (128 hosts)
                /26: 255.255.255.192 (64 hosts)
                /27: 255.255.255.224 (32 hosts)
                /28: 255.255.255.240 (16 hosts)
                /29: 255.255.255.248 (8 hosts)
                /30: 255.255.255.252 (4 addresses, 2 usable hosts)

  -n COUNT   [Optional] Number of open IPs to list (default: 1).

  -v          Verbose

Results:
  /tmp/hosts_used.txt     - hostname, MAC, IP for all hosts found by nmap
  /tmp/open_ips.txt       - first COUNT unused IPs in the subnet (not seen by nmap)
```

## Examples

Default stops at the 1st match

```
# ./ip-scout.sh -n 10.136.41.0 -m 16
[2026-01-05 16:26:07] bpatridge-a8 [OK] Scanning 10.136.41.0/16 with nmap:  |
[2026-01-05 16:39:38] bpatridge-a8 [OK] nmap scan completed in 00:13:31
[2026-01-05 16:39:38] bpatridge-a8 [OK] Parsing nmap output into /tmp/hosts_used.txt ...
[2026-01-05 16:39:38] bpatridge-a8 [OK] Collected 5026 used hosts into /tmp/hosts_used.txt
[2026-01-05 16:39:38] bpatridge-a8 [OK] Finding first 1 open IP(s) in 10.136.41.0/16 ...
10.136.41.6
[2026-01-05 16:39:38] bpatridge-a8 [OK] Saved 1 open IP(s) to /tmp/open_ips.txt

# cat /tmp/open_ips.txt
10.136.41.6
```

&nbsp;

Verbose option

```
# ./ip-scout.sh -n 10.136.41.0 -m 16 -c 2 -v
[2026-01-05 17:21:55] bpatridge-a8 [VERBOSE] Subnet octet#1 = 10
[2026-01-05 17:21:55] bpatridge-a8 [VERBOSE] Subnet octet#2 = 136
[2026-01-05 17:21:55] bpatridge-a8 [VERBOSE] Subnet octet#3 = 41
[2026-01-05 17:21:55] bpatridge-a8 [VERBOSE] Subnet octet#4 = 0
[2026-01-05 17:21:55] bpatridge-a8 [VERBOSE] [COMMAND] nmap -sn --system-dns 10.136.41.0/16
[2026-01-05 17:21:55] bpatridge-a8 [OK] Scanning 10.136.41.0/16 with nmap
Starting Nmap 7.92 ( https://nmap.org ) at 2026-01-05 17:21 MST
Nmap scan report for vrrp506.tintri.com (10.136.0.1)
Host is up (0.0051s latency).
MAC Address: 00:00:5E:00:01:4D (Icann, Iana Department)
Nmap scan report for vrrp506a.tintri.com (10.136.0.2)
Host is up (0.0071s latency).
MAC Address: CC:16:7E:7D:17:2F (Cisco Systems)
Nmap scan report for vrrp506b.tintri.com (10.136.0.3)
Host is up (0.0087s latency).
MAC Address: F8:0B:CB:1B:91:23 (Cisco Systems)
Nmap scan report for uww-ti-itdc02.tintri.com (10.136.0.4)
Host is up (0.0046s latency).
MAC Address: 00:50:56:90:92:10 (VMware)
...
...
MAC Address: 00:50:56:90:BE:18 (VMware)
Nmap scan report for uww-ti-dcops-rke-worker03.tintri.com (10.136.255.223)
Host is up (0.0012s latency).
MAC Address: 00:50:56:90:9C:7F (VMware)
Nmap done: 65536 IP addresses (5037 hosts up) scanned in 724.16 seconds
[2026-01-05 17:34:09] bpatridge-a8 [OK] nmap scan completed in 00:12:14
[2026-01-05 17:34:09] bpatridge-a8 [OK] Parsing nmap output into /tmp/hosts_used.txt ...
[2026-01-05 17:34:09] bpatridge-a8 [OK] Collected 5036 used hosts into /tmp/hosts_used.txt
[2026-01-05 17:34:09] bpatridge-a8 [OK] Finding first 2 open IP(s) in 10.136.41.0/16 ...
10.136.41.6
10.136.41.15
[2026-01-05 17:34:09] bpatridge-a8 [OK] Saved 2 open IP(s) to /tmp/open_ips.txt
#

# cat /tmp/open_ips.txt
10.136.41.6
10.136.41.15


```

&nbsp;
