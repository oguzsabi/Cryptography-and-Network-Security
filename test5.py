import multiprocessing
import socket

my_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip = '192.168.1.32'
lock = multiprocessing.Lock()


def port_scan(port):
    try:
        my_socket.connect((ip, port))
        with lock:
            print("Port: " + str(port) + " is open----------------")
        my_socket.close()
    except:
        with lock:
            print("Port: " + str(port) + " is closed")
        my_socket.close()


if __name__ == "__main__":
    ports = []
    for i in range(1, 100):
        ports.append(i)

    pool = multiprocessing.Pool()
    pool.map(port_scan, ports)
    pool.close()
    pool.join()
    print("All Done!")
