import subprocess
import sys
import socket
import os

ip_range = input("\nPlease enter an ip (Ex: 192.168.1.2) or ip range (Ex: 192.168.1.20-45):\n")
if ip_range:
    ip_check = ''
    ip_base = ''
    tcpdump_command = ''

    ip_range_start = ''
    ip_range_end = ''
    dot_count = 0
    range_check = False
    for i in ip_range:
        if len(ip_range) < 7:
            print("\n\nPlease enter correct values for the ip\n\n")
            sys.exit()

        try:
            if dot_count < 3:
                ip_base += i
                ip_check += i
            if i != "." and i != "-":
                int(i)
            if i == ".":
                dot_count += 1
            elif dot_count == 3:
                if i == "-":
                    range_check = True
                    continue
                if not range_check:
                    ip_check += i
                    ip_range_start += i
                if range_check:
                    ip_range_end += i
            if dot_count > 3:
                print("\n\nPlease enter correct values for the ip\n\n")
                sys.exit()
        except ValueError:
            print("\n\nPlease enter correct values for the ip\n\n")
            sys.exit()

    try:
        socket.inet_aton(ip_check)
        print("IP good!")
    except socket.error:
        print("IP bad!")

    if len(ip_range_end) > 0 and int(ip_range_end) < 256:
        if int(ip_range_end) < int(ip_range_start):
            tmp = ip_range_start
            ip_range_start = ip_range_end
            ip_range_end = tmp
    else:
        ip_range_end = ip_range_start

    hosts_string = ""

    ip_src_dst_host = input("\nWill these ip(s) be source(s), destination(s) or both (Ex: src, dst, both):\n")

    if ip_src_dst_host == "src":
        for i in range(int(ip_range_start), int(ip_range_end) + 1):
            if i == int(ip_range_start):
                hosts_string += ("src " + ip_base + str(i))
            else:
                hosts_string += (" or src " + ip_base + str(i))

    if ip_src_dst_host == "dst":
        for i in range(int(ip_range_start), int(ip_range_end) + 1):
            if i == int(ip_range_start):
                hosts_string += ("dst " + ip_base + str(i))
            else:
                hosts_string += (" or dst " + ip_base + str(i))

    if ip_src_dst_host == "both":
        for i in range(int(ip_range_start), int(ip_range_end) + 1):
            if i == int(ip_range_start):
                hosts_string += ("host " + ip_base + str(i))
            else:
                hosts_string += (" or host " + ip_base + str(i))


else:
    print("\n\nPlease specify an ip or an ip range\n\n")
    sys.exit()

protocol_input = input("\nPlease select a protocol (Ex: tcp, udp, both):\n")

if protocol_input:
    if protocol_input.lower() == "tcp":
        tcpdump_protocol = "-n tcp "

    elif protocol_input.lower() == "udp":
        tcpdump_protocol = "-n udp "

    elif protocol_input.lower() == "both":
        tcpdump_protocol = "-n "

    else:
        print("\n\nPlease specify a correct protocol\n\n")
        sys.exit()

else:
    print("\n\nPlease specify a correct protocol\n\n")
    sys.exit()


port_range_input = input(
        "\nPlease select source or destination port(s) (Ex: src 80, dst 20-30) or both (Ex: port 80, port 20-80):\n")

if port_range_input:
    port_src = False
    port_dst = False
    port_both = False
    if port_range_input[:3] == "src" and port_range_input[3] == " ":
        port_range = port_range_input[4:]
        port_src = True

    elif port_range_input[:3] == "dst" and port_range_input[3] == " ":
        port_range = port_range_input[4:]
        port_dst = True

    elif port_range_input[:4] == "port" and port_range_input[4] == " ":
        port_range = port_range_input[5:]
        port_both = True

    else:
        print("\n\nPlease specify src or dst and enter correct port values\n\n")
        sys.exit()

    port_start = ''
    port_end = ''
    dash_check = False

    for i in port_range:
        if i == "-":
            dash_check = True
            continue

        if not dash_check:
            port_start += i

        elif dash_check:
            port_end += i

    try:
        if port_start:
            int(port_start)
        if port_end:
            int(port_end)
    except ValueError:
        print("\n\nPlease enter correct values for port(s)\n\n")

    if port_end:
        ports_for_port_range = "portrange " + port_start + "-" + port_end
    else:
        ports_for_port_range = "port " + port_start

else:
    print("\n\nPlease specify a port or a port range\n\n")
    sys.exit()

print("sudo tcpdump " + tcpdump_protocol + ports_for_port_range + " and '(" + hosts_string + ")'")
os.system("sudo tcpdump " + tcpdump_protocol + ports_for_port_range + " and '(" + hosts_string + ")'")
