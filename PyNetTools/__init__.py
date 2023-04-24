#!/usr/bin/env python3
"""_summary_
    Small library of functions to ping IP addresses or domain names.
    Author:
        - https://github.com/Carlos-Corona

    License:
        - MIT License
        - https://opensource.org/licenses/MIT
        
    Version:
        - 0.0.1
        - https://github.com/Carlos-Corona/pingp/releases
    
Returns:
    _type_: _description_
"""

import subprocess
import socket
import struct
import re


class PingService:
    def __init__(self, count=5):
        self.count = count

    def ping(self, ip):
        if self.check_IP_Syntax(ip):
            self.ping_cmd = f"ping {ip} -c {self.count}"
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


class WakeOnLanService:
    def __init__(self):
        pass

    def wake_on_lan(self, MAC_ADDRESS):
        if self.check_MAC_Syntax(MAC_ADDRESS):
            print(f"{MAC_ADDRESS} is a valid MAC address.")
            mac_bytes = MAC_ADDRESS.split(":")
            magic_packet = b'\xff' * 6 + \
                (struct.pack('!6B', *[int(x, 16) for x in mac_bytes])) * 16
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


if __name__ == "__main__":
    print("PingP is a library of functions to ping IP addresses or domain names.")
    print("Please run the test suite (test_pingp.py) to see if the library is working correctly.")
    print("If you want to use the library, please import it into your program.")
    # To Do: Add test suite.