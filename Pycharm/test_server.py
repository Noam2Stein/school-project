"""
Full integration test aligned with protocol definitions.
No pytest. Minimal structural changes. Only correctness + cleanup.
"""

import shutil
import threading
from pathlib import Path
from time import sleep
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lib.encryption import PublicKey
from lib.socket_wrapper import ServerListener, try_connect_to_server
from lib.request_handler import Client, handle_next_request
from lib.database import Database
from lib.request_response import (
    SignupRequest, SignupResponse,
    LoginRequest, LoginResponse,
    FetchRequest, FetchResponse,
    PushRequest, PushResponse,
    SendRequest, SendResponse,
    CreateItemRequest, CreateItemResponse,
    ItemRequest, ItemResponse,
    EncryptItemRequest, EncryptItemResponse,
    ReleaseItemRequest, ReleaseItemResponse,
)

# ============================================================
# helpers
# ============================================================


def recv(conn):
    rvar = conn.recv()
    while rvar is None:
        rvar = conn.recv()
    return rvar


class Check:
    def __init__(self):
        self.passed = 0

    def ok(self, label: str, condition: bool):
        if not condition:
            raise AssertionError(f"FAIL: {label}")
        self.passed += 1
        print(f"  PASS  {label}")


from lib.encryption import keypair, decrypt, PrivateKey, PublicKey
from lib.encode_default import str_to_bytes, bytes_to_str

def decrypt_item(blob: bytes, priv_key) -> bytes:
    blob_str = blob.decode("latin-1")
    if ":" in blob_str:
        blob_str = blob_str.split(":", 1)[1]
    encrypted_bytes = str_to_bytes(blob_str.strip())
    return decrypt(priv_key, encrypted_bytes)


# ============================================================
# Keypair for EncryptItemRequest
# ============================================================

rsa_priv, rsa_pub = keypair("correct horse battery staple")


# ============================================================
# server setup
# ============================================================

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "__test_data__"

shutil.rmtree(DATA_DIR, ignore_errors=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

db = Database(str(DATA_DIR))
listener = ServerListener()
clients = []
stop = threading.Event()


def server_loop():
    with ThreadPoolExecutor(max_workers=10) as pool:
        while not stop.is_set():
            for _ in range(10):
                conn = listener.accept()
                if conn:
                    clients.append(Client(conn))

            for c in list(clients):
                if getattr(c, "is_handling", False) or not c.conn.has_input():
                    continue

                c.is_handling = True
                pool.submit(handle_next_request, db, c)

            sleep(0.001)


threading.Thread(target=server_loop, daemon=True).start()
sleep(0.05)


def connect():
    c = try_connect_to_server()
    while c is None:
        c = try_connect_to_server()
    return c


conn_a = connect()
conn_b = connect()
conn_anon = connect()

print("Clients connected.\n")

check = Check()


# ============================================================
# SIGNUP
# ============================================================

print("=== Signup ===")

conn_a.send(SignupRequest(
    email="usera@test.com",
    auth_key="111111",
    private_info="priv_a",
    public_key=PublicKey(rsa_pub),
))
r = SignupResponse(**recv(conn_a))

check.ok("signup A success", r.is_success)
check.ok("signup A email not taken flag", not r.email_is_taken)

conn_b.send(SignupRequest(
    email="userb@test.com",
    auth_key="333333",
    private_info="priv_b",
    public_key=PublicKey(rsa_pub),
))
r = SignupResponse(**recv(conn_b))
check.ok("signup B success", r.is_success)


# duplicate
conn_a.send(SignupRequest("usera@test.com", "999", "x", PublicKey(rsa_pub)))
r = SignupResponse(**recv(conn_a))
check.ok("duplicate fails", not r.is_success)
check.ok("duplicate flagged", r.email_is_taken)


# ============================================================
# LOGIN
# ============================================================

print("\n=== Login ===")

conn_a.send(LoginRequest("usera@test.com", "111111"))
r = LoginResponse(**recv(conn_a))
check.ok("login A success", r.is_success)

conn_b.send(LoginRequest("userb@test.com", "333333"))
r = LoginResponse(**recv(conn_b))
check.ok("login B success", r.is_success)


# ============================================================
# FETCH
# ============================================================

print("\n=== Fetch ===")

conn_anon.send(FetchRequest())
r = FetchResponse(**recv(conn_anon))

check.ok("anon blocked", not r.is_success)
check.ok("anon flagged", r.not_logged_in)

conn_a.send(FetchRequest())
r = FetchResponse(**recv(conn_a))

check.ok("fetch success", r.is_success)
check.ok("users exist", "usera@test.com" in r.user_emails)
check.ok("keys aligned", len(r.user_emails) == len(r.user_public_keys))


# ============================================================
# PUSH
# ============================================================

print("\n=== Push ===")

conn_a.send(PushRequest(
    private_info="updated_priv_a",
    messages=["enc_msg_1", "enc_msg_2"],
))
r = PushResponse(**recv(conn_a))
check.ok("push success", r.is_success)

conn_a.send(FetchRequest())
r = FetchResponse(**recv(conn_a))
check.ok("push persisted", r.private_info == "updated_priv_a")


# ============================================================
# SEND
# ============================================================

print("\n=== Send ===")

conn_a.send(SendRequest("userb@test.com", "hello b"))
r = SendResponse(**recv(conn_a))
check.ok("send success", r.is_success)

conn_b.send(FetchRequest())
r = FetchResponse(**recv(conn_b))
check.ok("message delivered", "hello b" in r.messages)


# ============================================================
# CREATE ITEM
# ============================================================

print("\n=== Create Item ===")

conn_a.send(CreateItemRequest(bytes_to_str(b"data"), "777777"))
item_id = CreateItemResponse(**recv(conn_a)).id

check.ok("item id exists", isinstance(item_id, str))


# ============================================================
# ITEM REQUEST
# ============================================================

print("\n=== Item Request ===")

conn_a.send(ItemRequest(item_id, "777777"))
r = ItemResponse(**recv(conn_a))

check.ok("item fetch success", r.is_success)
check.ok("no release keys initially", r.release_key_contents == [])


# ============================================================
# ENCRYPT ITEM
# ============================================================

print("\n=== Encrypt Item ===")

conn_a.send(EncryptItemRequest(
    id=item_id,
    auth_key="777777",
    public_key=PublicKey(rsa_pub),
    prefix="PREFIX:",
))
r = EncryptItemResponse(**recv(conn_a))

check.ok("encrypt success", r.is_success)

conn_a.send(ItemRequest(item_id, "777777"))
r = ItemResponse(**recv(conn_a))

raw = r.contents.encode("latin-1")
check.ok("prefix applied", raw.startswith(b"PREFIX:"))

decrypted = decrypt_item(raw, rsa_priv)
check.ok("decrypt ok", decrypted == b"data")


# ============================================================
# RELEASE ITEM
# ============================================================

print("\n=== Release Item ===")

conn_a.send(ReleaseItemRequest(
    id=item_id,
    auth_key="777777",
    info="release_alpha",
    expires=datetime(2027, 1, 1).isoformat(),
))
r = ReleaseItemResponse(**recv(conn_a))

check.ok("release success", r.is_success)


conn_a.send(ItemRequest(item_id, "777777"))
r = ItemResponse(**recv(conn_a))

check.ok("release stored", len(r.release_key_contents) == 1)


# ============================================================
# teardown
# ============================================================

stop.set()
listener.close()
shutil.rmtree(DATA_DIR, ignore_errors=True)

print(f"\n{check.passed} checks passed.")
print("All tests passed.")
