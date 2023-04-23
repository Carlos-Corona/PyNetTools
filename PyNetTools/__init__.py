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
# class PingIP thah contains above code

class PingService:
    def __init__(self, count = 5):
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
        
    def check_IP_Syntax(self,ip):
        # Define the regular expression pattern for an IP address
        ip_pattern = r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$"
        
        # Define the regular expression pattern for a domain name
        domain_pattern = r"^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$"
        
        # Use regex to match the patterns against the input
        ip_match = re.match(ip_pattern, ip)
        domain_match = re.match(domain_pattern, ip)
        
        # Check if the input matches either pattern
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
            magic_packet = b'\xff' * 6 + (struct.pack('!6B', *[int(x, 16) for x in mac_bytes])) * 16
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                s.sendto(magic_packet, ('<broadcast>', 9))
        else:
            print(f"{MAC_ADDRESS} is not a valid MAC address.")
    
    def create_magic_packages(self, MAC_ADDRESS: str):
        # Remove the colon separator from the MAC address
        MAC_ADDRESS = MAC_ADDRESS.replace(":", "")
        # Create the magic packet using bytes.fromhex()
        magic_packet = bytes.fromhex("FF" * 6 + MAC_ADDRESS * 16)
        return magic_packet

    def create_magic_packet(self,macaddress: str) -> bytes:
        """
        Create a magic packet.

        A magic packet is a packet that can be used with the for wake on lan
        protocol to wake up a computer. The packet is constructed from the
        mac address given as a parameter.

        Args:
            macaddress: the mac address that should be parsed into a magic packet.

        """
        if len(macaddress) == 17:
            sep = macaddress[2]
            macaddress = macaddress.replace(sep, "")
        elif len(macaddress) == 14:
            sep = macaddress[4]
            macaddress = macaddress.replace(sep, "")
        if len(macaddress) != 12:
            raise ValueError("Incorrect MAC address format")
        return bytes.fromhex("F" * 12 + macaddress * 16)



    def check_MAC_Syntax(self,MAC_ADDRESS):
        
        pattern = r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$"

        match = re.match(pattern, MAC_ADDRESS)

        if match:
            return True
        else:
            return False
        
        
if __name__ == "__main__":  # pragma: nocover
    print("PingP is a library of functions to ping IP addresses or domain names.")
    print("Please run the test suite (test_pingp.py) to see if the library is working correctly.")
    print("If you want to use the library, please import it into your program.")