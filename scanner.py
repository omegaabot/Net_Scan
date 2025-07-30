import ipaddress
import socket
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, Ether, srp
from tqdm import tqdm

def discover_devices(target_ip):
    """
    Discovers devices on the network using ARP requests.
    Returns a list of dictionaries, each with an 'ip' and 'mac'.
    """
    print(f"[*] Discovering devices on {target_ip}...")
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp
    
    result = srp(packet, timeout=3, verbose=0)[0]
    
    clients = []
    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
    
    clients.sort(key=lambda x: ipaddress.IPv4Address(x['ip']))
    print(f"[✔] Discovered {len(clients)} devices.")
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
        print(f"Couldn't connect to {ip}")
    return None

def scan_host(ip, port_range, max_threads=200):
    """
    Scans a range of ports on a single host using multiple threads.
    """
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(scan_port, ip, port): port for port in port_range}
        
        for future in as_completed(future_to_port):
            port = future.result()
            if port is not None:
                open_ports.append(port)
    
    return sorted(open_ports)

def main():
    print("[*] Simple Network Scanner\n")
    target_ip = input("Enter target subnet (e.g., 192.168.1.0/24): ").strip()

    print("\n--- Port Scan Options ---")
    print("q - Quick scan of common ports")
    print("f - Full scan of all 65,535 ports (very slow)")
    print("c - Custom scan of user-specified ports")
    scan_choice = input("Enter your choice [q]: ").strip().lower() or 'q'

    port_range = []
    if scan_choice == 'f':
        port_range = range(1, 65536)
        print("[*] Full port scan selected. This may take a very long time.")
    elif scan_choice == 'c':
        custom_ports_str = input("Enter custom ports (comma-separated, e.g., 80,443,8080): ").strip()
        try:
            port_range = [int(p.strip()) for p in custom_ports_str.split(',')]
            print(f"[*] Custom scan selected for ports: {port_range}")
        except ValueError:
            print("[!] Invalid input. Defaulting to a quick scan.")
            scan_choice = 'q'
    
    if scan_choice == 'q' or not port_range:
        port_range = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 3306, 3389, 8080, 8443]
        print("[*] Quick scan selected.")
    
    clients = discover_devices(target_ip)
    if not clients:
        print("\n[!] No devices found. Exiting.")
        return

    print(f"\n[*] Starting port scan on {len(clients)} discovered devices...")

    for client in tqdm(clients, desc="Scanning Hosts"):
        ip = client['ip']
        client['open_ports'] = scan_host(ip, port_range)

    print("\n\n[✔] Scan Complete. Results:\n" + "="*25)
    
    final_results = []
    for client in clients:
        ip = client['ip']
        mac = client['mac']
        ports = client.get('open_ports', [])
        
        if ports:
            ports_str = ", ".join(map(str, ports))
            print(f"  IP: {ip} ({mac})")
            print(f"  Open Ports: {ports_str}\n")
        
        final_results.append([ip, mac, ", ".join(map(str, ports))])
    
    output_filename = "scan_results.csv"
    with open(output_filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["IP", "MAC", "Open Ports"])
        writer.writerows(final_results)
    
    print(f"[✔] Results also saved to {output_filename}")

if __name__ == "__main__":
    main()