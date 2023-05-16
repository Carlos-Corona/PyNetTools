from PyNetTools import PingService, WakeOnLanService

if __name__ == "__main__":
    # create various prints that show the program logo and what it does
    PingME = PingService(count=50)
    MagicMe = WakeOnLanService()
    print("Wake on Lan")
    print("Wake up your computer by sending a magic packet to the broadcast address of the network.")
    print("This program will send a magic packet to the broadcast address of the network.")
    
    MAC_ADDRESS = "60:a4:b7:b2:b0:db"
    IP_ADDRESS = "192.168.100.66"
    
    MagicMe.wake_on_lan(MAC_ADDRESS)
    print("Magic packet sent to " + MAC_ADDRESS)
    PingME.ping(IP_ADDRESS)
