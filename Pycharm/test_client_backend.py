"""
Full integration test for ClientBackend.
No pytest.
Starts a real server and uses the actual backend API.
"""

from __future__ import annotations

import shutil
import threading
from pathlib import Path
from time import sleep
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from uuid import UUID

from lib.client_backend import ClientBackend
from lib.socket_wrapper import ServerListener
from lib.request_handler import Client, handle_next_request
from lib.database import Database


# ============================================================
# helpers
# ============================================================

class Check:
    def __init__(self):
        self.passed = 0

    def ok(self, label: str, condition: bool):
        if not condition:
            raise AssertionError(f"FAIL: {label}")

        self.passed += 1
        print(f"  PASS  {label}")


def wait_until_done(fn, *args):
    while True:
        result = fn(*args)

        if result != "wait":
            return result

        sleep(0.01)


# ============================================================
# server setup
# ============================================================

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "__client_backend_test_data__"

shutil.rmtree(DATA_DIR, ignore_errors=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

db = Database(str(DATA_DIR))

listener = ServerListener()

clients: list[Client] = []

stop = threading.Event()


def server_loop():
    with ThreadPoolExecutor(max_workers=16) as pool:
        while not stop.is_set():
            for _ in range(10):
                conn = listener.accept()

                if conn is not None:
                    clients.append(Client(conn))

            for client in list(clients):
                if getattr(client, "is_handling", False) or not client.conn.has_input():
                    continue

                client.is_handling = True
                pool.submit(
                    handle_next_request,
                    db,
                    client,
                )

            sleep(0.001)


threading.Thread(
    target=server_loop,
    daemon=True,
).start()

sleep(0.05)

print("Server started.\n")

check = Check()

# ============================================================
# backend setup
# ============================================================

backend_a = ClientBackend()
backend_b = ClientBackend()

EMAIL_A = "usera@test.com"
PASSWORD_A = "password_a"

EMAIL_B = "userb@test.com"
PASSWORD_B = "password_b"

# ============================================================
# signup
# ============================================================

print("=== Signup ===")

r = wait_until_done(
    backend_a.signup,
    EMAIL_A,
    PASSWORD_A,
    "User A",
)

check.ok(
    "signup A",
    r == "done",
)

r = wait_until_done(
    backend_b.signup,
    EMAIL_B,
    PASSWORD_B,
    "User B",
)

check.ok(
    "signup B",
    r == "done",
)

# duplicate signup

r = wait_until_done(
    backend_a.signup,
    EMAIL_A,
    PASSWORD_A,
    "User A",
)

check.ok(
    "duplicate signup rejected",
    r == "already exists",
)

# ============================================================
# login
# ============================================================

print("\n=== Login ===")

backend_a = ClientBackend()

r = wait_until_done(
    backend_a.login,
    EMAIL_A,
    PASSWORD_A,
)

check.ok(
    "login success",
    r == "done",
)

check.ok(
    "logged into correct email",
    backend_a.logged_into_email() == EMAIL_A,
)

# ============================================================
# fetch
# ============================================================

print("\n=== Fetch ===")

r = wait_until_done(
    backend_a.fetch_from_server,
)

check.ok(
    "fetch success",
    r == "done",
)

emails = backend_a.global_user_emails()

check.ok(
    "global emails loaded",
    isinstance(emails, list),
)

check.ok(
    "user B exists globally",
    EMAIL_B in emails,
)

description = backend_a.global_user_description(EMAIL_B)

check.ok(
    "description loaded",
    isinstance(description, str),
)

# ============================================================
# create item
# ============================================================

print("\n=== Create Item ===")

r = wait_until_done(
    backend_a.create_item,
    "hello.txt",
    b"hello world",
)

check.ok(
    "create item success",
    r == "done",
)

item_ids = backend_a.my_item_ids()

check.ok(
    "my items returns list",
    isinstance(item_ids, list),
)

check.ok(
    "item created",
    len(item_ids) == 1,
)

item_id = item_ids[0]

check.ok(
    "item id is uuid",
    isinstance(item_id, UUID),
)

# ============================================================
# item metadata
# ============================================================

print("\n=== Item Metadata ===")

name = backend_a.item_name(item_id)

check.ok(
    "item name correct",
    name == "hello.txt",
)

method = backend_a.item_encryption_method(item_id)

check.ok(
    "encryption method exists",
    isinstance(method, str),
)

locked = backend_a.item_is_locked(item_id)

check.ok(
    "item lock status valid",
    isinstance(locked, bool),
)

# ============================================================
# read item
# ============================================================

print("\n=== Read Item ===")

contents = wait_until_done(
    backend_a.read_item,
    item_id,
)

check.ok(
    "read returned bytes",
    isinstance(contents, bytes),
)

check.ok(
    "contents match",
    contents == b"hello world",
)

# ============================================================
# release item
# ============================================================

print("\n=== Release Item ===")

until = datetime.now() + timedelta(days=1)

r = wait_until_done(
    backend_a.release_item,
    item_id,
    until,
)

check.ok(
    "release item success",
    r == "done",
)

released = backend_a.has_released_item(item_id)

check.ok(
    "release state true",
    released is True,
)

released_until = backend_a.released_item_timelimit(item_id)

check.ok(
    "release timelimit exists",
    isinstance(released_until, datetime),
)

# ============================================================
# invite user
# ============================================================

print("\n=== Invite User ===")

r = wait_until_done(
    backend_a.invite_user_to_item,
    EMAIL_B,
    item_id,
)

check.ok(
    "invite success",
    r == "done",
)

# ============================================================
# fetch invitations
# ============================================================

print("\n=== Invitations ===")

r = wait_until_done(
    backend_b.login,
    EMAIL_B,
    PASSWORD_B,
)

check.ok(
    "login B success",
    r == "done",
)

r = wait_until_done(
    backend_b.fetch_from_server,
)

check.ok(
    "fetch B success",
    r == "done",
)

invites = backend_b.my_item_invitation_ids()

check.ok(
    "invitation list exists",
    isinstance(invites, list),
)

check.ok(
    "received invitation",
    item_id in invites,
)

# ============================================================
# join item
# ============================================================

print("\n=== Join Item ===")

r = wait_until_done(
    backend_b.join_item,
    item_id,
)

check.ok(
    "join item success",
    r == "done",
)

my_items_b = backend_b.my_item_ids()

check.ok(
    "joined item moved to owned list",
    item_id in my_items_b,
)

# ============================================================
# delete item
# ============================================================

print("\n=== Delete Item ===")

r = wait_until_done(
    backend_a.delete_item,
    item_id,
)

check.ok(
    "delete success",
    r == "done",
)

remaining = backend_a.my_item_ids()

check.ok(
    "item removed after delete",
    item_id not in remaining,
)

# ============================================================
# teardown
# ============================================================

stop.set()

listener.close()

shutil.rmtree(DATA_DIR, ignore_errors=True)

print(f"\n{check.passed} checks passed.")
print("All tests passed.")
