import multiprocessing
import subprocess
import os


def ping_scan(task_q, results_q):
    dev_null = open(os.devnull, 'w')
    while True:
        ip = task_q.get()
        if ip is None:
            break

        try:
            subprocess.check_call(['ping', '-c1', ip], stdout=dev_null)
            results_q.put(ip)
        except:
            pass


if __name__ == '__main__':
    pool_size = 255

    jobs = multiprocessing.Queue()
    results = multiprocessing.Queue()

    pool = [multiprocessing.Process(target=ping_scan, args=(jobs, results)) for i in range(pool_size)]

    for p in pool:
        p.start()

    for i in range(1, 256):
        jobs.put('192.168.1.{0}'.format(i))

    for p in pool:
        jobs.put(None)

    for p in pool:
        p.join()

    while not results.empty():
        ip = results.get()
        print(ip)
