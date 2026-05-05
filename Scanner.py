import nmap
import sys
import argparse
import socket
import ipaddress


def validate_target(target: str) -> bool:
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass

    try:
        socket.gethostbyname(target)
        return True
    except socket.gaierror:
        return False


SCAN_PROFILES = {
    "standard": "-T4 -sV --open",
    "quick": "-T4 -F --open",
    "full": "-T4 -sV -p- --open",
}


def run_scan(target, profile="standard", ports=None):
    nm = nmap.PortScanner()

    args = SCAN_PROFILES.get(profile, SCAN_PROFILES["standard"])

    try:
        if ports:
            nm.scan(hosts=target, ports=ports, arguments=args)
        else:
            nm.scan(hosts=target, arguments=args)
    except Exception as e:
        print("Scan error:", e)
        sys.exit(1)

    found = False

    for host in nm.all_hosts():
        if nm[host].state() != "up":
            continue

        print("\nHost:", host)

        for proto in nm[host].all_protocols():
            ports_list = nm[host][proto].keys()

            for port in sorted(ports_list):
                data = nm[host][proto][port]

                if data["state"] == "open":
                    found = True
                    service = data.get("name", "unknown")
                    print(f"{port}\topen\t{service}")

    if not found:
        print("No open ports found.")


def main():
    parser = argparse.ArgumentParser(description="Simple Nmap Network Scanner")

    parser.add_argument("target", help="IP, domain, or CIDR range")
    parser.add_argument("--profile", choices=SCAN_PROFILES.keys(), default="standard")
    parser.add_argument("--ports", help="Port range (e.g. 22,80,443 or 1-1000)")

    args = parser.parse_args()

    if not validate_target(args.target):
        print("Invalid target")
        sys.exit(1)

    run_scan(args.target, args.profile, args.ports)


if __name__ == "__main__":
    main()
