import shutil
from pathlib import Path
from time import sleep
from concurrent.futures import ThreadPoolExecutor

from lib.socket_wrapper import ServerListener
from lib.request_handler import Client, handle_next_request
from lib.database import Database

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(f"{SCRIPT_DIR}/__data__")
DATA_DIR.mkdir(parents=True, exist_ok=True)
db = Database(DATA_DIR.__str__())

listener = ServerListener()
clients = []

with ThreadPoolExecutor(max_workers=10) as thread_pool:
    while True:
        for _ in range(50):
            conn = listener.accept()
            if conn is None:
                break
            
            clients.append(Client(conn))

        for client in clients:
            if getattr(client, "is_handling", False) or not client.conn.has_input():
                continue

            client.is_handling = True
            thread_pool.submit(handle_next_request, db, client)

        sleep(0.001)
