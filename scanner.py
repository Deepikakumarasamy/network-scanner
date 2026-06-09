import socket
import ipaddress
import concurrent.futures
import datetime
import sys
import json
COMMON_PORTS = {
    21: "FTP" ,
    22: "SSH" ,
    23: "TELNET" ,
    53: "DNS" ,
    80: "HTTP" ,
    110: "POP3" ,
    143: "IMAP" ,
    443: "HTTPS" ,
    445: "SMB" ,
    3306: "MySQL" ,
    3389: "RDP" ,
    8080: "HTTP-Alt" ,
    8443: "HTTPS-Alt"
}
SECURITY_NOTES = {
    21: "CRITICAL - FTP transmits credentials in plain text",
    22: "INFO - SSH open, check for brute force protection",
    23: "CRITICAL - Telnet is unencrypted, replace with SSH",
    25: "WARNING - SMTP open, check for open relay",
    3306: "CRITICAL - MySQL exposed to network, should be localhost only",
    3389: "HIGH - RDP exposed, high brute force risk",
    445: "HIGH - SMB open, check for EternalBlue vulnerability"
}
def scan_port(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        return result == 0
    except socket.error:
        return False
def grab_banner(ip, port, timeout=2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((str(ip), port))
        
        # Send HTTP request for web ports
        if port in [80, 8080, 443, 8443]:
            sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
        
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        sock.close()
        return banner[:100] if banner else "No banner"
    except:
        return "No banner"
def scan_host(ip):
    open_ports = []

    for port, service in COMMON_PORTS.items():
        if scan_port(ip, port):
           banner = grab_banner(ip, port)
           open_ports.append({
        "port": port,
        "service": service,
        "banner": banner
    })
    return {
        "ip": str(ip),
        "open_ports": open_ports,
        "status": "alive" if open_ports else "no open ports found"
    }

def ping_host(ip, timeout=1):
    return scan_port(ip, 80, timeout) or scan_port(ip, 22, timeout)
def generate_ip_range(start_ip, end_ip):
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)

    ips = []
    current = start
    while current <=end:
        ips.append(current)
        current +=1
    return ips

def print_banner():
    """Prints tool banner"""
    print("=" * 60)
    print("         NETWORK SCANNER - Security Tool")
    print("         Educational Use Only")
    print("=" * 60)
    print(f"Scan started: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)


def print_results(results):
    print("\n" + "=" * 60)
    print("SCAN RESULTS")
    print("=" * 60)
    
    hosts_with_ports = [r for r in results if r["open_ports"]]
    
    if not hosts_with_ports:
        print("No open ports found on any host.")
        return
    
    for host in hosts_with_ports:
        print(f"\nHost: {host['ip']}")
        print(f"Status: {host['status']}")
        print("Open Ports:")
        for port_info in host["open_ports"]:
            note = SECURITY_NOTES.get(port_info['port'], "")
            banner = port_info.get('banner', 'No banner')
            if note:
                  print(f"  {port_info['port']:5d} | {port_info['service']:12} | {note}")
            else:
                 print(f"  {port_info['port']:5d} | {port_info['service']}")
            if banner and banner != "No banner":
                 print(f"          Banner: {banner[:80]}")
    
    print(f"\nTotal hosts with open ports: {len(hosts_with_ports)}")


def save_results(results, filename):
    
    with open(filename, 'w') as f:
        f.write(f"Network Scan Report\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 60 + "\n\n")
        
        for host in results:
            if host["open_ports"]:
                f.write(f"Host: {host['ip']}\n")
                f.write(f"Status: {host['status']}\n")
                f.write("Open Ports:\n")
                for port_info in host["open_ports"]:
                    note = SECURITY_NOTES.get(port_info['port'], "")
                    banner = port_info.get('banner', 'No banner')
                    if note:
                        f.write(f"  {port_info['port']:5d} | {port_info['service']:12} | {note}\n")
                    else:
                        f.write(f"  {port_info['port']:5d} | {port_info['service']}\n")
                    if banner and banner != "No banner":
                        f.write(f"          Banner: {banner[:80]}\n")
                f.write("\n")
    
    print(f"\nResults saved to {filename}")

def save_results_json(results, filename):
    output = {
        "scan_date": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "total_hosts_scanned": len(results),
        "hosts_with_open_ports": len([r for r in results if r["open_ports"]]),
        "results": results
    }
    with open(filename, 'w') as f:
        json.dump(output, f, indent=4)
    print(f"JSON results saved to {filename}")

def scan_network(start_ip, end_ip):
    print(f"\nScanning range: {start_ip} to {end_ip}")
    
    # Generate IP list
    ip_list = generate_ip_range(start_ip, end_ip)
    print(f"Total hosts to scan: {len(ip_list)}")
    print("Scanning... (this may take a moment)\n")
    
    results = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {
            executor.submit(scan_host, ip): ip 
            for ip in ip_list
        }
        
        completed = 0
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            results.append(result)
            completed += 1
            
            # Progress indicator
            progress = (completed / len(ip_list)) * 100
            print(f"\rProgress: {progress:.1f}% ({completed}/{len(ip_list)})", 
                  end="", flush=True)
    
    print()  # New line after progress
    return results


def main():
    print_banner()
    
    print("\nNETWORK SCANNER")
    print("-" * 40)
    print("WARNING: Only scan networks you own or have permission to scan.")
    print("Unauthorised scanning is illegal.\n")
    
    # Get scan target from user
    print("Options:")
    print("1. Scan single IP")
    print("2. Scan IP range")
    print("3. Scan local network (192.168.1.1-254)")
    
    choice = input("\nEnter choice (1/2/3): ").strip()
    
    if choice == "1":
        ip = input("Enter IP address: ").strip()
        start_ip = end_ip = ip
        
    elif choice == "2":
        start_ip = input("Enter start IP: ").strip()
        end_ip = input("Enter end IP: ").strip()
        
    elif choice == "3":
        start_ip = "192.168.1.1"
        end_ip = "192.168.1.10"
        print(f"Scanning {start_ip} to {end_ip}")
        
    else:
        print("Invalid choice")
        sys.exit(1)
    
    # Validate IP addresses
    try:
        ipaddress.IPv4Address(start_ip)
        ipaddress.IPv4Address(end_ip)
    except ValueError:
        print("Invalid IP address format")
        sys.exit(1)
    
    # Run the scan
    results = scan_network(start_ip, end_ip)
    
    # Display results
    print_results(results)
    
    # Save results
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_results_{timestamp}.txt"
    save_results(results, filename)
    json_filename = f"scan_results_{timestamp}.json"
    save_results_json(results, json_filename)


if __name__ == "__main__":
    main()