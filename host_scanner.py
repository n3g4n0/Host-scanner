import subprocess
import argparse
from scapy.all import ARP, Ether, srp, IP, UDP, sr1
import ipaddress
import socket
import sys

# ARP Scan
def arp_scan(ip):
    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    result = srp(arp_request_broadcast, timeout=3, verbose=False)[0]

    for i in range(0, len(result)):
        print("IP:", result[i][1].psrc, "\t", "MAC:", result[i][1].hwsrc)

# Ping Scan for entire subnet
def ping_scan(network):
    # Generate all IP addresses 
    network = ipaddress.ip_network(network, strict=False)
    for ip in network.hosts():
        command = ["ping", "-c", "1", str(ip)]
        response = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if response.returncode == 0:
            print(f"Ping Scan: {ip} is alive")

# TCP Connect Scan
def tcp_connect_scan(ip, port):
    try:
        # Create a socket object and attempt to connect to the host on the given port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Timeout after 1 second
        result = sock.connect_ex((ip, port))
        if result == 0:  # Connection was successful
            print(f"TCP Connect Scan: Port {port} on {ip} is open")
        sock.close()
    except socket.error:
        pass

# UDP Scan
def udp_scan(ip, port):
    try:
        # Create a UDP packet using Scapy
        udp_packet = IP(dst=ip) / UDP(dport=port)
        response = sr1(udp_packet, timeout=2, verbose=False)

        # Analyze the response
        if response is None:
            print(f"UDP Scan: Port {port} on {ip} is open/filtered (no response)")
        elif response.haslayer(UDP):
            print(f"UDP Scan: Port {port} on {ip} is open")
    except Exception as e:
        print(f"Error during UDP Scan on {ip}:{port} - {e}")

# Parse command-line arguments
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Target IP or network")
    parser.add_argument("-a", "--arp", help="Perform ARP scan", action="store_true")
    parser.add_argument("-p", "--ping", help="Perform Ping scan", action="store_true")
    parser.add_argument("-t", "--tcp", help="Perform TCP connect scan", action="store_true")
    parser.add_argument("-u", "--udp", help="Perform UDP scan", action="store_true")
    parser.add_argument("--ports", help="Ports to scan (default=80,443 for TCP, 53 for UDP)")
    return parser.parse_args()

def main():
    args = get_args()

    # Default: Run all scans
    if not any([args.arp, args.ping, args.tcp, args.udp]):
        args.arp = args.ping = args.tcp = args.udp = True

    # Perform ARP scan if option is chosen
    if args.arp:
        print("Performing ARP scan...")
        arp_scan(args.target)

    # Perform Ping scan if option is chosen
    if args.ping:
        print("Performing Ping scan...")
        ping_scan(args.target)

    # Perform TCP connect scan if option is chosen
    if args.tcp:
        print("Performing TCP Scan...")
        if args.ports:
            # Split the ports string and convert to integers
            try:
                ports = [int(port) for port in args.ports.split(",")]
            except ValueError:
                print("Error: Invalid port number in the list.")
                sys.exit(1)
        else:
            # If no ports are provided, use default ports
            print("No ports provided, using default ports: 80,443")
            ports = [80, 443]  # Default ports

        # Iterate over the hosts in the target network
        if ipaddress.ip_network(args.target, strict=False):
            network = ipaddress.ip_network(args.target, strict=False)
            for ip in network.hosts():
                for port in ports:
                    tcp_connect_scan(str(ip), port)
        else:
            for port in ports:
                tcp_connect_scan(args.target, port)

    # Perform UDP scan if option is chosen
    if args.udp:
        print("Performing UDP Scan...")
        if args.ports:
            try:
                ports = [int(port) for port in args.ports.split(",")]
            except ValueError:
                print("Error: Invalid port number in the list.")
                sys.exit(1)
        else:
            print("No ports provided, using default port: 53")
            ports = [53]  # Common UDP ports (DNS)

        # Iterate over the hosts in the target network
        if ipaddress.ip_network(args.target, strict=False):
            network = ipaddress.ip_network(args.target, strict=False)
            for ip in network.hosts():
                for port in ports:
                    udp_scan(str(ip), port)
        else:
            for port in ports:
                udp_scan(args.target, port)

if __name__ == "__main__":
    main()
