from time import sleep
from concurrent.futures import ThreadPoolExecutor

from lib.socket_wrapper import ServerListener
from lib.request_handler import Client, handle_next_request

listener = ServerListener()
clients = []

with ThreadPoolExecutor(max_workers=10) as thread_pool:
    while True:
        for _ in range(50):
            conn = listener.accept()
            if conn == None:
                break
            
            clients.append(Client(conn))

        for client in clients:
            if not client.conn.has_input():
                continue

            thread_pool.submit(handle_next_request, client)

        sleep(0.001)
