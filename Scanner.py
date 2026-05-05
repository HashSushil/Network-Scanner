import nmap
import socket

def scan(target):
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("Invalid target")
        return

    scanner = nmap.PortScanner()

    print(f"\nScanning {ip} (ports 1-1024)...\n")

    scanner.scan(hosts=ip, arguments='-p 1-1024 -sV')

    found = False

    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()

            for port in sorted(ports):
                port_data = scanner[host][proto][port]
                
                if port_data['state'] == "open":
                    found = True
                    service = port_data['name']
                    print(f"{port:<5} open  {service}")

    if not found:
        print("No open ports found.")

if __name__ == "__main__":
    target = input("Enter target IP or domain: ")
    scan(target)
