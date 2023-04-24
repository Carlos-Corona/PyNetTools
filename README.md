# PyNetTools

`PyNetTools` is a Python library that allows you to wake up devices on your local network using Wake-on-LAN and scan the local network for connected devices using a massive ping and ARP requests. This library provides a simple way to send magic packets, which are used in the Wake-on-LAN protocol, and discover devices on your network.

### Features
Wake up devices on your local network using Wake-on-LAN
Scan local network for connected devices using ping and ARP
Simple and easy-to-use 

### Try it

Download the library

```bash
git clone https://github.com/(***))/pywakeonlan.git
```
from root path `../PyNetTools_Project/`

- This program will send a magic packet to the broadcast address of the network, after will send `n` number of pings to try to reach the computer
``` bash
python -m Examples.main

[crowne@fedora PyNetTools_Project]$ python -m Examples.main
60:a4:c7:b2:b0:da is a valid MAC address.
Magic packet sent to 10:d4:b7:b2:a0:da
PING 192.168.100.66 (192.168.100.66) 56(84) bytes of data.
64 bytes from 192.168.100.66: icmp_seq=1 ttl=64 time=0.218 ms

--- 192.168.100.66 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 0.218/0.218/0.218/0.000 ms
192.168.100.66 is reachable.
```


### Massive Ping and ARP

To perform a massive ping and ARP scan on your local network, you can use the provided masive_ping.py script.

***Broken

### Version: 0.0.1

### To-Do
- Improve error handling and input validation
- Add support for IPv6 addresses
- Add command-line interface
- Improve capabilities
- Include more capabilities as `ip addr`, `hostname -i` and more...

### License
This project is licensed under the MIT License.

### Disclaimer
Use this library responsibly and within the terms of use of the networks you have permission to access. Misuse of this library can cause increased network traffic and potentially affect other devices or network performance. The authors are not responsible for any damage or consequences that may arise from the use of this library.