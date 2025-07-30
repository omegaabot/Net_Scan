import ipaddress
import socket
import csv
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, Ether, srp
from tqdm import tqdm

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080, 8443]

def discover_devices(target_ip):
    """
    Discovers devices on the network using ARP requests.
    Returns a list of dictionaries, each with an 'ip' and 'mac'.
    """
    logging.info(f"Discovering devices on {target_ip}...")
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    clients.sort(key=lambda x: ipaddress.IPv4Address(x['ip']))
    logging.info(f"Discovered {len(clients)} device(s).")
    return clients

def scan_port(ip, port):
    """
    Tries to connect to a specific IP and port.
    Returns the port number if open, otherwise returns None.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((ip, port)) == 0:
                return port
    except socket.error:
        logging.error(f"Couldn't connect to {ip}:{port}")
    return None

def scan_host(ip, port_range, max_threads=200):
    """
    Scans a range of ports on a single host using multiple threads.
    Returns a sorted list of open ports.
    """
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in port_range}

        for future in as_completed(future_to_port):
            port = future.result()
            if port is not None:
                open_ports.append(port)

    return sorted(open_ports)

def export_to_csv(results, filename='scan_results.csv'):
    """
    Exports scan results to a CSV file.
    """
    with open(filename, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['IP', 'MAC', 'Open Ports'])
        for res in results:
            writer.writerow([res['ip'], res['mac'], ','.join(str(port) for port in res['open_ports'])])

def parse_ports(port_str):
    """
    Parses a comma-separated string of ports into a list of ints.
    """
    try:
        return [int(p.strip()) for p in port_str.split(',') if p.strip().isdigit()]
    except ValueError:
        logging.error("Invalid port input. Please supply comma-separated port numbers.")
        return []

def main():
    parser = argparse.ArgumentParser(description="Concurrent Network Discovery and Port Scanner")
    parser.add_argument('--subnet', type=str, help='Target subnet (e.g., 192.168.1.0/24)')
    parser.add_argument('--scan', choices=['q', 'f', 'c'], default='q', help='Scan type: q=Quick, f=Full, c=Custom')
    parser.add_argument('--ports', type=str, help='Custom ports (comma-separated, e.g., 80,443,8080)')
    parser.add_argument('--output', type=str, default='scan_results.csv', help='Output CSV filename')
    args = parser.parse_args()

    print("[*] Simple Network Scanner\n")
    # Interactive fallback if not provided as arguments
    target_ip = args.subnet or input("Enter target subnet (e.g., 192.168.1.0/24): ").strip()
    if not target_ip:
        logging.error("No subnet provided.")
        return

    print("\n--- Port Scan Options ---")
    print("q - Quick scan of common ports")
    print("f - Full scan of all 65,535 ports (very slow)")
    print("c - Custom scan of user-specified ports")

    scan_choice = args.scan or (input("Enter your choice [q]: ").strip().lower() or 'q')
    port_range = []

    if scan_choice == 'f':
        port_range = range(1, 65536)
        print("[*] Full port scan selected. This may take a very long time.")
    elif scan_choice == 'c':
        custom_ports_str = args.ports or input("Enter custom ports (comma-separated, e.g., 80,443,8080): ").strip()
        port_range = parse_ports(custom_ports_str)
        if not port_range:
            print("[!] Invalid input. Defaulting to a quick scan.")
            scan_choice = 'q'
    if scan_choice == 'q' or not port_range:
        port_range = COMMON_PORTS
        print("[*] Quick scan selected.")

    try:
        clients = discover_devices(target_ip)
    except Exception as e:
        logging.error(f"Device discovery failed: {e}")
        return

    if not clients:
        logging.warning("No devices found on the network.")
        return

    print("\nScanning hosts for open ports...\n")
    results = []
    for client in tqdm(clients, desc="Scanning hosts"):
        ip = client['ip']
        mac = client['mac']
        open_ports = scan_host(ip, port_range)
        results.append({'ip': ip, 'mac': mac, 'open_ports': open_ports})
        print(f"{ip} ({mac}): {open_ports}")

    export_to_csv(results, args.output)
    print(f"\n[✔] Results also saved to {args.output}")

if __name__ == '__main__':
    main()