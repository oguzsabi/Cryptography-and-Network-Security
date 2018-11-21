import multiprocessing
from datetime import datetime


def trying(arg):
    print(arg*arg)


if __name__ == "__main__":

    array = []
    for i in range(1, 10000000):
        array.append(i)

    t1 = datetime.now()
    process = multiprocessing.Pool()
    process.map(trying, array)
    process.close()
    process.join()

    t2 = datetime.now()

    t3 = datetime.now()
    for i in range(1, 10000000):
        print(i * i)

    t4 = datetime.now()

    print("Total time (multiprocess): " + str(t2 - t1))
    print("Total time: " + str(t4 - t3))
