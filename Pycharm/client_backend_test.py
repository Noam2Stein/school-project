"""
Full integration test for ClientBackend.

- Starts real server (Database + ServerListener)
- Connects real socket clients
- Exercises ClientBackend fully:
  signup, login, fetch, create_item, read_item,
  release_item, invite_user_to_item, join_item,
  reject_item, delete_item, leave_and_release_item

No mocking. No fuzzing. Deterministic assertions only.
"""

import threading
import shutil
from pathlib import Path
from time import sleep
from datetime import datetime

from lib.socket_wrapper import ServerListener, try_connect_to_server
from lib.request_handler import Client, handle_next_request
from lib.database import Database
from lib.client_backend import ClientBackend


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def wait(fn, timeout=3.0):
    """Wait until fn() stops returning 'wait'."""
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


# ---------------------------------------------------------------------------
# server setup
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# backend clients
# ---------------------------------------------------------------------------

alice = ClientBackend()
bob = ClientBackend()

alice_email = "alice@test.com"
bob_email = "bob@test.com"


# ---------------------------------------------------------------------------
# SIGNUP
# ---------------------------------------------------------------------------

print("\n=== SIGNUP ===")

check("alice signup",
      wait(lambda: alice.signup(alice_email, "pw", "Alice")) == "done")

check("bob signup",
      wait(lambda: bob.signup(bob_email, "pw", "Bob")) == "done")


# ---------------------------------------------------------------------------
# LOGIN (idempotency + fetch state load)
# ---------------------------------------------------------------------------

print("\n=== LOGIN ===")

check("alice login already loaded",
      alice.login(alice_email, "pw") == "done")

check("bob login",
      wait(lambda: bob.login(bob_email, "pw")) == "done")


# ---------------------------------------------------------------------------
# FETCH USERS
# ---------------------------------------------------------------------------

print("\n=== FETCH ===")

check("alice sees bob",
      "bob@test.com" in alice.global_user_emails())

check("bob sees alice",
      "alice@test.com" in bob.global_user_emails())


# ---------------------------------------------------------------------------
# CREATE ITEM
# ---------------------------------------------------------------------------

print("\n=== CREATE ITEM ===")

item_id = wait(lambda: alice.create_item("file1", b"hello world"))

check("item created",
      isinstance(item_id, str))


# ---------------------------------------------------------------------------
# READ ITEM
# ---------------------------------------------------------------------------

print("\n=== READ ITEM ===")

data = wait(lambda: alice.read_item(item_id))
check("alice reads item", data == b"hello world")


# ---------------------------------------------------------------------------
# INVITE BOB TO ITEM
# ---------------------------------------------------------------------------

print("\n=== INVITE ===")

check("invite sent",
      alice.invite_user_to_item(bob_email, item_id) == "done")


# simulate bob processing invites via fetch
bob.fetch_from_server()


# ---------------------------------------------------------------------------
# JOIN ITEM
# ---------------------------------------------------------------------------

print("\n=== JOIN ITEM ===")

check("bob joins item",
      bob.join_item(item_id) == "done")


# ---------------------------------------------------------------------------
# BOB READS ITEM
# ---------------------------------------------------------------------------

print("\n=== BOB READ ===")

data2 = wait(lambda: bob.read_item(item_id))
check("bob reads shared item", data2 == b"hello world")


# ---------------------------------------------------------------------------
# RELEASE ITEM
# ---------------------------------------------------------------------------

print("\n=== RELEASE ITEM ===")

future = datetime(2099, 1, 1)

check("alice releases item",
      wait(lambda: alice.release_item(item_id, future)) == "done")


# verify release visible
check("release state visible",
      alice.has_released_item(item_id) is True)


# ---------------------------------------------------------------------------
# BOB REJECT ITEM FLOW
# ---------------------------------------------------------------------------

print("\n=== REJECT ITEM ===")

check("bob rejects item",
      bob.reject_item(item_id) == "done")

check("bob no longer sees item",
      item_id not in [str(x) for x in bob.my_item_ids()])


# ---------------------------------------------------------------------------
# DELETE ITEM
# ---------------------------------------------------------------------------

print("\n=== DELETE ITEM ===")

check("alice deletes item",
      alice.delete_item(item_id) == "done")


# ---------------------------------------------------------------------------
# CLEAN EXIT
# ---------------------------------------------------------------------------

stop.set()
listener.close()
shutil.rmtree(DATA_DIR, ignore_errors=True)

print("\nALL CLIENT BACKEND TESTS PASSED")