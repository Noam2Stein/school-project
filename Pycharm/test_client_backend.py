"""
Full integration test for refactored ClientBackend.
"""

import threading
import shutil
from pathlib import Path
from time import sleep
from datetime import datetime

from lib.socket_wrapper import ServerListener
from lib.request_handler import Client, handle_next_request
from lib.database import Database
from lib.client_backend import ClientBackend


def wait(fn, timeout=5.0):
    import time
    start = time.time()

    while True:
        r = fn()
        if r != "wait":
            return r
        if time.time() - start > timeout:
            raise TimeoutError("wait() timeout")
        time.sleep(0.01)


def check(label, cond):
    if not cond:
        raise AssertionError(label)
    print("PASS:", label)


SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "__client_backend_test_data__"

shutil.rmtree(DATA_DIR, ignore_errors=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

db = Database(str(DATA_DIR))
listener = ServerListener()

clients = []
stop = threading.Event()


def server_loop():
    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=8) as pool:
        while not stop.is_set():
            for _ in range(10):
                conn = listener.accept()
                if conn is None:
                    break
                clients.append(Client(conn))

            for c in list(clients):
                if c.conn.has_input():
                    pool.submit(handle_next_request, db, c)


threading.Thread(target=server_loop, daemon=True).start()
sleep(0.1)


alice = ClientBackend()
bob = ClientBackend()

alice_email = "alice@test.com"
bob_email = "bob@test.com"


print("\n=== SIGNUP ===")

check("alice signup",
      wait(lambda: alice.signup(alice_email, "pw", "Alice")) == "done")

check("bob signup",
      wait(lambda: bob.signup(bob_email, "pw", "Bob")) == "done")


print("\n=== LOGIN ===")

check("alice login (idempotent)",
      alice.login(alice_email, "pw") == "done")

check("bob login",
      wait(lambda: bob.login(bob_email, "pw")) == "done")


print("\n=== FETCH USERS ===")

check("alice sees bob",
      "bob@test.com" in alice._user_emails)

check("bob sees alice",
      "alice@test.com" in bob._user_emails)


print("\n=== CREATE ITEM ===")

check("item created",
      wait(lambda: alice.create_item("file1", b"hello world")) == "done")

item_id = next(iter(alice._items().keys()))


print("\n=== READ ITEM (ALICE) ===")

data = wait(lambda: alice.read_item(item_id))

check("alice reads item",
      data == b"hello world")


print("\n=== RELEASE ITEM ===")

future = datetime(2099, 1, 1)

check("alice releases item",
      wait(lambda: alice.release_item(item_id, future)) == "done")


check("release state visible",
      alice._items()[str(item_id)]["released"] is True)


print("\n=== BOB DIRECT ACCESS ===")

data2 = wait(lambda: bob.read_item(item_id))

check("bob reads item",
      data2 == b"hello world")


stop.set()
listener.close()
shutil.rmtree(DATA_DIR, ignore_errors=True)

print("\nALL CLIENT BACKEND TESTS PASSED")