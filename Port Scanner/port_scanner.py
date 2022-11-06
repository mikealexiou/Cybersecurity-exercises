import queue
import socket
import threading

target_ip = "127.0.0.1"
queue = queue.Queue()
open_ports = list()


def portScanner(port):
    try:
        new_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        new_socket.connect((target_ip, port))
        return True
    except:
        return False


def getPorts(status):
    if status == 1:
        for port in range(1, 1024):
            queue.put(port)
    elif status == 2:
        for port in range(1, 49152):
            queue.put(port)
    elif status == 3:
        ports = [20, 21, 22, 23, 25, 53, 80, 110, 443]
        for port in ports:
            queue.put(port)
    elif status == 4:
        ports = input('Enter your ports : ')
        ports = ports.split()
        ports = list(map(int, ports))
        for port in ports:
            queue.put(port)


def worker():
    while not queue.empty():
        port = queue.get()
        if portScanner(port):
            print('Port ' + str(port) + ' is open!')
            open_ports.append(port)


def start_scanner(threads, status):
    getPorts(status)
    thread_list = list()

    for t in range(threads):
        thread = threading.Thread(target=worker)
        thread_list.append(thread)

    for thread in thread_list:
        thread.start()

    for thread in thread_list:
        thread.join()

    print('Open ports are:', open_ports)

status = int(input("Give status: "))
start_scanner(500, status)
