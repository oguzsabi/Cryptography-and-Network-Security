import nmap
from datetime import datetime

t1 = datetime.now()
# ports_dat = open("ports.dat", "a")
ip = '192.168.138.159'
# nm = nmap.PortScanner()
#
# ports_dat.write("Host: ->" + ip + "\n")
# for i in range(1, 65000):
#     nm.scan(ip, str(i))
#     if nm.all_hosts():
#         print(i)
#         proto = nm[ip].all_protocols()[0]
#         if len(nm[ip][proto][i]["name"]) > 0:
#             ports_dat.write(
#                 "Port: ->" + str(i) + "   Service: ->" + nm[ip][proto][i]["name"] + "   Status: ->" + nm[ip][proto][i][
#                     "state"] + "\n")
#         else:
#             ports_dat.write(
#                 "Port: ->" + str(i) + "   Service: ->unknown" + "   Status: ->" + nm[ip][proto][i][
#                     "state"] + "\n")
# ports_dat.write("\n")


t2 = datetime.now()
print("total time: " + str(t2 - t1))
