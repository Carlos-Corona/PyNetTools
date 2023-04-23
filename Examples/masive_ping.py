import os
import re
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor


def ping_ip(ip_address: str) -> bool:
    param = "-n" if os.sys.platform == "win32" else "-c"
    command = ["ping", param, "1", ip_address]
    return subprocess.call(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def get_mac_address(ip_address: str) -> str:
    platform = os.sys.platform
    arp_cmd = f"arp -a {ip_address}" if platform == "win32" else f"arp -n {ip_address}"
    output = os.popen(arp_cmd).read()
    mac_address = re.search(r"(([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2}))", output)
    if mac_address:
        return mac_address.group(0)
    else:
        return None


def ping_and_get_mac(ip_address: str):
    if ping_ip(ip_address):
        mac_address = get_mac_address(ip_address)
        if mac_address:
            print(f"IP: {ip_address}, MAC: {mac_address}")
            
            return ip_address, mac_address
    return None


if __name__ == "__main__":
    network = "192.168.100.0/24"
    ip_network = ipaddress.IPv4Network(network, strict=False)

    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(ping_and_get_mac, [str(ip) for ip in ip_network.hosts()]))

    devices = [result for result in results if result is not None]

    print(f"Found {len(devices)} devices in network {network}:")
    for ip_address, mac_address in devices:
        print(f"IP: {ip_address}, MAC: {mac_address}")
