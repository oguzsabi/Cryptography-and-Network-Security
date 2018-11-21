import nmap
import multiprocessing

nm = nmap.PortScanner()
ports_dat = open("ports.dat", "a")


def port_identification(port):
    print("1")
    ip = '192.168.138.63'
    print("2")
    try:
        nm.scan(ip, port)
        if nm.all_hosts():
            print("3")
            proto = nm[ip].all_protocols()[0]

            if len(nm[ip][proto][i]["name"]) > 0:
                print("4")
                ports_dat.write(
                    "Port: ->" + str(i) + "   Service: ->" + nm[ip][proto][i]["name"] + "   Status: ->" +
                    nm[ip][proto][i][
                        "state"] + "\n")
            else:
                print("5")
                ports_dat.write(
                    "Port: ->" + str(i) + "   Service: ->unknown" + "   Status: ->" + nm[ip][proto][i][
                        "state"] + "\n")

    except:
        print("hata var oc")
        ports_dat.write("Gotune sok")
        pass


if __name__ == "__main__":
    lock = multiprocessing.Lock()
    open("ports.dat", "w+").close()

    ports = []
    for i in range(1, 1025):
        ports.append(str(i))

    print("6")
    pool = multiprocessing.Pool()
    print("7")
    pool.map(port_identification, ports)
    print("8")
    pool.close()
    print("9")
    pool.join()

    print("All Done!")
