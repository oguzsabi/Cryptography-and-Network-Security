import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import subprocess
import socket
import sys
from datetime import datetime
import os
import nmap
import multiprocessing

# Check what time the scan started
t1 = datetime.now()
try:
    for port in range(20, 81):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex(('192.168.1.32', port))
        if result == 0:
            print( "Port {}: 	 Open".format(port))
        else:
            print("Port {}: 	 Closed".format(port))
        sock.close()

except KeyboardInterrupt:
    print("You pressed Ctrl+C")
    sys.exit()

except socket.gaierror:
    print('Hostname could not be resolved. Exiting')
    sys.exit()

except socket.error:
    print("Couldn't connect to server")
    sys.exit()

# Checking the time again
t2 = datetime.now()

# Calculates the difference of time, to see how long it took to run the script
total = t2 - t1

# Printing the information to screen
print('Scanning Completed in: ', total)

# BACKUP ===============================================================================================================
# alive = subprocess.call("sudo nmap -oN icmp.dat -v0 --open -sn " + options.ping, shell=True)
