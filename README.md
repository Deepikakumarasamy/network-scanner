# Network Scanner

A Python-based network reconnaissance tool that scans IP ranges,
identifies live hosts, and detects open ports and running services.

## What it does
- Scans single IPs or IP ranges
- Detects 14 common ports and identifies their services
- Uses concurrent threading for fast scanning
- Generates timestamped scan reports
- Saves results to file for documentation

## Security concepts demonstrated
- TCP three-way handshake — port detection via connect_ex()
- Network reconnaissance — systematic host and port discovery
- Common service identification — maps ports to services
- Concurrent scanning — ThreadPoolExecutor for performance

## Technical details
- Language: Python 3
- Key libraries: socket, ipaddress, concurrent.futures
- Scanning method: TCP connect scan
- Threading: 50 concurrent workers

## How to run

### Requirements
Python 3.6 or higher

### Installation
git clone https://github.com/YOUR-USERNAME/network-scanner
cd network-scanner

### Usage
python3 scanner.py

### Options
1. Scan single IP address
2. Scan IP range
3. Scan local network

## Example output
Host: 192.168.1.1
Status: alive
Open Ports:
   80 | HTTP
  443 | HTTPS
   22 | SSH

## Important
Only scan networks you own or have explicit permission to scan.
Unauthorised network scanning is illegal.

## What I learned
- TCP socket programming in Python
- How port scanners work at the network level
- Threading for concurrent network operations
- How common services map to port numbers
- Network reconnaissance techniques used in security assessments

## Author
Deepika — Cybersecurity security engineering student
