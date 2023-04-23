from PyNetTools import PingService, WakeOnLanService
from dotenv import load_dotenv
import os
from wakeonlan import send_magic_packet
import time

if __name__ == "__main__":
    # create various prints that show the program logo and what it does
    load_dotenv()
    PingME = PingService(count=1)
    MagicMe = WakeOnLanService()
    print("Wake on Lan")
    print("Wake up your computer by sending a magic packet to the broadcast address of the network.")
    print("This program will send a magic packet to the broadcast address of the network.")
    
    MAC = os.getenv("MAC_ADDRESS")
    IP = os.getenv("IP_ADDRESS")
    
    print("Magic packet sent to " + MAC)
    

    MagicMe.wake_on_lan(MAC)
    PingME.ping(IP)
