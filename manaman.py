import multiprocessing
import subprocess
import os
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *


def ping_scan(ips, alives):
    dev_null = open(os.devnull, 'w')
    while True:
        ip = ips.get()
        if ip is None:
            break

        try:
            subprocess.check_call(['ping', '-c1', ip], stdout=dev_null)
            alives.put(ip)
        except:
            pass


if __name__ == '__main__':
    icmp_dat = open("icmp.dat", "w+")
    icmp_dat.close()
    icmp_dat = open("icmp.dat", "a+")

    ip_address = multiprocessing.Queue()
    live_hosts = multiprocessing.Queue()
    processes = []

    for i in range(256):
        processes.append(multiprocessing.Process(target=ping_scan, args=(ip_address, live_hosts)))

    for i in processes:
        i.start()

    origin = '192.168.1.'
    for i in range(1, 256):
        ip_address.put(origin + '{0}'.format(i))

    for i in processes:
        ip_address.put(None)

    for i in processes:
        i.join()

    print("Live Hosts Are: ")
    while not live_hosts.empty():
        host = live_hosts.get()
        icmp_dat.write(host + "\n")
        print(host)
