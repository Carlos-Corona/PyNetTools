#!/usr/bin/env python3
"""_summary_
    Small library of functions to ping IP addresses or domain names.
    Author:
        - https://github.com/Carlos-Corona

    License:
        - MIT License
        - https://opensource.org/licenses/MIT
        
    Version:
        - 0.1
        - https://github.com/Carlos-Corona/PyNetTools.git
    
Returns:
    _type_: _description_
"""

import subprocess
import socket
import struct
import re
import os
import ipaddress
from concurrent.futures import ThreadPoolExecutor

#First Parent
class PingService:
    def __init__(self, count=5):
        self.count = count

    def ping(self, ip):
        if self.check_IP_Syntax(ip):
            param = "-n" if os.sys.platform == "win32" else "-c"
            self.ping_cmd = f"ping {ip} {param} {self.count}"
            response = subprocess.call(self.ping_cmd, shell=True)
            if response == 0:
                print(f"{ip} is reachable.")
                return True
            else:
                print(f"{ip} is not reachable.")
                return False
        else:
            print(f"{ip} is a valid IP address or domain name.")
            return False

    def check_IP_Syntax(self, ip):
        ip_pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
        domain_pattern = r"^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$"
        ip_match = re.match(ip_pattern, ip)
        domain_match = re.match(domain_pattern, ip)
        if ip_match:
            octets = ip_match.groups()
            for octet in octets:
                if int(octet) > 255:
                    return False
            return True
        elif domain_match:
            return True
        else:
            return False

#Second Parent
class WakeOnLanService(PingService):  # Inherit from PingService
    def __init__(self, count=5):
        super().__init__(count)
        
    def wake_on_lan(self, MAC_ADDRESS):
        if self.check_MAC_Syntax(MAC_ADDRESS):
            print(f"{MAC_ADDRESS} is a valid MAC address.")
            mac_bytes = MAC_ADDRESS.split(":")
            #magic_packet = b'\xff' * 6 + \(struct.pack('!6B', *[int(x, 16) for x in mac_bytes])) * 16
            magic_packet = self.create_magic_packet(MAC_ADDRESS)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.sendto(magic_packet, ('<broadcast>', 9))
        else:
            print(f"{MAC_ADDRESS} is not a valid MAC address.")

    def create_magic_packages(self, MAC_ADDRESS: str):
        MAC_ADDRESS = MAC_ADDRESS.replace(":", "")
        magic_packet = bytes.fromhex("FF" * 6 + MAC_ADDRESS * 16)
        return magic_packet

    def create_magic_packet(self, MAC_ADDRESS: str) -> bytes:
        if len(MAC_ADDRESS) == 17:
            sep = MAC_ADDRESS[2]
            MAC_ADDRESS = MAC_ADDRESS.replace(sep, "")
        elif len(MAC_ADDRESS) == 14:
            sep = MAC_ADDRESS[4]
            MAC_ADDRESS = MAC_ADDRESS.replace(sep, "")
        if len(MAC_ADDRESS) != 12:
            raise ValueError("Incorrect MAC address format")
        return bytes.fromhex("F" * 12 + MAC_ADDRESS * 16)

    def check_MAC_Syntax(self, MAC_ADDRESS):
        pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"
        match = re.match(pattern, MAC_ADDRESS)
        if match:
            return True
        else:
            return False

#Child
class NetTools(WakeOnLanService):
    def __init__(self, network = "192.168.100.0/24",worker_count = None,count = 5):
        super().__init__(count)
        self.network = network
        self.worker_count = worker_count

    def get_mac_address(self, ip_address: str) -> str:
        platform = os.sys.platform
        arp_cmd = f"arp -a {ip_address}" if platform == "win32" else f"arp -n {ip_address}"
        output = os.popen(arp_cmd).read()
        mac_address = self.MacAddressExtractor(output)
        if mac_address:
            return mac_address
        else:
            return None
    def MacAddressExtractor(self,MAC_ADDRESS: str)  -> str:
        left =  1
        rigth = 1
        sub_string = ""
        for n in range(len(MAC_ADDRESS)):
            if MAC_ADDRESS[n] != " " and left != rigth:
                left = n
                rigth = n
                sub_string = ""
            if MAC_ADDRESS[n] == " " and left == rigth or MAC_ADDRESS[n] == "\n" and left == rigth:
                rigth = n            
                if super().check_MAC_Syntax(sub_string):
                    return sub_string
                sub_string = ""
            sub_string = sub_string + MAC_ADDRESS[n]
        return None
        
    def ping_and_get_mac(self,ip_address: str):
        if super().ping(ip_address):
            mac_address = self.get_mac_address(ip_address)
            if mac_address:
                print(f"IP: {ip_address}, MAC: {mac_address}")
                return ip_address, mac_address
        return None

    def discover_devices(self):
        network = ipaddress.IPv4Network(self.network, strict=False)
        with ThreadPoolExecutor(max_workers=self.worker_count) as executor:
            results = list(executor.map(self.ping_and_get_mac, [str(ip) for ip in network.hosts()]))
        devices = [result for result in results if result is not None]
        return results, devices

if __name__ == "__main__":
    # To Do:
    #   Add tests
    #   As a standalone script
    print("Hello World")