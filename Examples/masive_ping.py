from PyNetTools import NetTools

if __name__ == "__main__":
    print("PingP is a library of functions to ping IP addresses or domain names.")
    print("Please run the test suite (test_pingp.py) to see if the library is working correctly.")
    print("If you want to use the library, please import it into your program.")
    # To Do: Add test suite.
    network = "192.168.100.0/24" # Network to perform the scan  
    net = NetTools(network,worker_count=1,count=1)
    
    ip_address, devices = net.discover_devices() # Discover devices in the network
    print(f"Found {len(devices)} devices in network {network}:")
    for ip_address, mac_address in devices:
        print(f"IP: {ip_address}, MAC: {mac_address}")