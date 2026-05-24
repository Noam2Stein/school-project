"""
Full integration test. Every request type is covered including EncryptItemRequest.
Two users. Every mutation is read back and verified. Every distinct failure flag
is asserted individually.
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

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def recv(conn):
    r = conn.recv()
    while r is None:
        r = conn.recv()
    return r

passed = 0

def check(label: str, condition: bool):
    global passed
    if not condition:
        raise AssertionError(f"FAIL: {label}")
    passed += 1
    print(f"  PASS  {label}")

def decrypt_item(blob: bytes, priv_key) -> bytes:
    """Mirror of encryption.py decrypt() — used to verify EncryptItem round-trip."""
    encrypted_key = blob[:256]
    nonce = blob[256:268]
    ciphertext = blob[268:]
    aes_key = priv_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)

# ---------------------------------------------------------------------------
# RSA key pair for EncryptItemRequest test
# ---------------------------------------------------------------------------

rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
rsa_pub_pem = rsa_priv.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
).decode("utf-8")

# ---------------------------------------------------------------------------
# server
# ---------------------------------------------------------------------------

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = SCRIPT_DIR / "__test_data__"
shutil.rmtree(DATA_DIR, ignore_errors=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

db = Database(str(DATA_DIR))
listener = ServerListener()
server_clients: list[Client] = []
stop_server = threading.Event()

def server_loop():
    with ThreadPoolExecutor(max_workers=10) as pool:
        while not stop_server.is_set():
            for _ in range(10):
                conn = listener.accept()
                if conn is None:
                    break
                server_clients.append(Client(conn))
            for c in list(server_clients):
                if c.conn.has_input():
                    pool.submit(handle_next_request, db, c)
            sleep(0.001)

threading.Thread(target=server_loop, daemon=True).start()
sleep(0.05)

def connect():
    c = try_connect_to_server()
    while c is None:
        c = try_connect_to_server()
    return c

conn_a = connect()   # user_a
conn_b = connect()   # user_b
conn_anon = connect()  # never logs in

print("Clients connected. Starting tests...\n")

# ---------------------------------------------------------------------------
# SIGNUP
# ---------------------------------------------------------------------------
print("=== Signup ===")

conn_a.send(SignupRequest(email="usera@test.com", auth_key=111111, private_info="priv_a", public_key=222222))
r = SignupResponse(**recv(conn_a))
check("signup success", r.is_succees)
check("signup: email_is_taken=False", not r.email_is_taken)

conn_b.send(SignupRequest(email="userb@test.com", auth_key=333333, private_info="priv_b", public_key=444444))
r = SignupResponse(**recv(conn_b))
check("user_b signup success", r.is_succees)

# duplicate — same connection
conn_a.send(SignupRequest(email="usera@test.com", auth_key=999, private_info="x", public_key=1))
r = SignupResponse(**recv(conn_a))
check("duplicate signup: is_succees=False", not r.is_succees)
check("duplicate signup: email_is_taken=True", r.email_is_taken)

# duplicate — different connection
conn_b.send(SignupRequest(email="usera@test.com", auth_key=111111, private_info="x", public_key=1))
r = SignupResponse(**recv(conn_b))
check("duplicate from other conn: is_succees=False", not r.is_succees)
check("duplicate from other conn: email_is_taken=True", r.email_is_taken)

# invalid email
conn_a.send(SignupRequest(email="not-an-email", auth_key=111111, private_info="x", public_key=1))
r = SignupResponse(**recv(conn_a))
check("invalid email: is_succees=False", not r.is_succees)
check("invalid email: email_is_taken=False", not r.email_is_taken)

# ---------------------------------------------------------------------------
# LOGIN
# ---------------------------------------------------------------------------
print("\n=== Login ===")

# wrong password
conn_a.send(LoginRequest(email="usera@test.com", auth_key=999999))
r = LoginResponse(**recv(conn_a))
check("wrong password: is_succees=False", not r.is_succees)
check("wrong password: incorrect_password=True", r.incorrect_password)
check("wrong password: user_doesnt_exist=False", not r.user_doesnt_exist)

# unknown user
conn_a.send(LoginRequest(email="ghost@test.com", auth_key=111111))
r = LoginResponse(**recv(conn_a))
check("unknown user: is_succees=False", not r.is_succees)
check("unknown user: user_doesnt_exist=True", r.user_doesnt_exist)
check("unknown user: incorrect_password=False", not r.incorrect_password)

# correct login
conn_a.send(LoginRequest(email="usera@test.com", auth_key=111111))
r = LoginResponse(**recv(conn_a))
check("user_a login: is_succees=True", r.is_succees)
check("user_a login: incorrect_password=False", not r.incorrect_password)
check("user_a login: user_doesnt_exist=False", not r.user_doesnt_exist)

conn_b.send(LoginRequest(email="userb@test.com", auth_key=333333))
r = LoginResponse(**recv(conn_b))
check("user_b login success", r.is_succees)

# ---------------------------------------------------------------------------
# FETCH
# ---------------------------------------------------------------------------
print("\n=== Fetch ===")

# not logged in
conn_anon.send(FetchRequest())
r = FetchResponse(**recv(conn_anon))
check("fetch without login: is_success=False", not r.is_success)
check("fetch without login: isnt_logged_in=True", r.isnt_logged_in)
check("fetch without login: user_emails empty", r.user_emails == [])
check("fetch without login: messages empty", r.messages == [])

# logged in — both users visible
conn_a.send(FetchRequest())
r = FetchResponse(**recv(conn_a))
check("fetch: is_success=True", r.is_success)
check("fetch: isnt_logged_in=False", not r.isnt_logged_in)
check("fetch: user_a in user_emails", "usera@test.com" in r.user_emails)
check("fetch: user_b in user_emails", "userb@test.com" in r.user_emails)
check("fetch: private_info correct", r.private_info == "priv_a")
check("fetch: no messages yet", r.messages == [])
check("fetch: user_emails and user_public_keys same length", len(r.user_emails) == len(r.user_public_keys))
check("fetch: user_emails and user_descriptions same length", len(r.user_emails) == len(r.user_descriptions))

idx_a = r.user_emails.index("usera@test.com")
idx_b = r.user_emails.index("userb@test.com")
check("fetch: user_a public key correct", r.user_public_keys[idx_a] == str(222222))
check("fetch: user_b public key correct", r.user_public_keys[idx_b] == str(444444))

# ---------------------------------------------------------------------------
# PUSH
# ---------------------------------------------------------------------------
print("\n=== Push ===")

# not logged in
conn_anon.send(PushRequest(private_info="hacked", messages=[]))
r = PushResponse(**recv(conn_anon))
check("push without login: is_succees=False", not r.is_succees)
check("push without login: isnt_logged_in=True", r.isnt_logged_in)

# valid push
conn_a.send(PushRequest(private_info="updated_priv_a", messages=["enc_msg_1", "enc_msg_2"]))
r = PushResponse(**recv(conn_a))
check("push: is_succees=True", r.is_succees)
check("push: isnt_logged_in=False", not r.isnt_logged_in)

# verify via fetch
conn_a.send(FetchRequest())
r = FetchResponse(**recv(conn_a))
check("push persisted: private_info updated", r.private_info == "updated_priv_a")
check("push persisted: messages updated", r.messages == ["enc_msg_1", "enc_msg_2"])

# push again to clear messages
conn_a.send(PushRequest(private_info="cleared", messages=[]))
check("second push success", PushResponse(**recv(conn_a)).is_succees)

conn_a.send(FetchRequest())
r = FetchResponse(**recv(conn_a))
check("second push: private_info updated", r.private_info == "cleared")
check("second push: messages cleared", r.messages == [])

# ---------------------------------------------------------------------------
# SEND
# ---------------------------------------------------------------------------
print("\n=== Send ===")

# not logged in
conn_anon.send(SendRequest(target_email="usera@test.com", content="spam"))
r = SendResponse(**recv(conn_anon))
check("send without login: is_succees=False", not r.is_succees)
check("send without login: not_logged_in=True", r.not_logged_in)
check("send without login: invalid_email=False", not r.invalid_email)
check("send without login: user_doesnt_exist=False", not r.user_doesnt_exist)

# invalid email format
conn_a.send(SendRequest(target_email="not-an-email", content="hello"))
r = SendResponse(**recv(conn_a))
check("send invalid email: is_succees=False", not r.is_succees)
check("send invalid email: invalid_email=True", r.invalid_email)
check("send invalid email: user_doesnt_exist=False", not r.user_doesnt_exist)
check("send invalid email: not_logged_in=False", not r.not_logged_in)

# valid email but user doesn't exist
conn_a.send(SendRequest(target_email="nobody@test.com", content="hello"))
r = SendResponse(**recv(conn_a))
check("send to unknown user: is_succees=False", not r.is_succees)
check("send to unknown user: user_doesnt_exist=True", r.user_doesnt_exist)
check("send to unknown user: invalid_email=False", not r.invalid_email)
check("send to unknown user: not_logged_in=False", not r.not_logged_in)

# a sends two messages to b
conn_a.send(SendRequest(target_email="userb@test.com", content="hello b, first message"))
r = SendResponse(**recv(conn_a))
check("a->b first send: is_succees=True", r.is_succees)
check("a->b first send: all error flags False", not r.invalid_email and not r.user_doesnt_exist and not r.not_logged_in)

conn_a.send(SendRequest(target_email="userb@test.com", content="hello b, second message"))
check("a->b second send success", SendResponse(**recv(conn_a)).is_succees)

# b fetches and verifies both messages arrived in order
conn_b.send(FetchRequest())
r = FetchResponse(**recv(conn_b))
check("b received exactly 2 messages", len(r.messages) == 2)
check("b first message correct", r.messages[0] == "hello b, first message")
check("b second message correct", r.messages[1] == "hello b, second message")

# b replies to a
conn_b.send(SendRequest(target_email="usera@test.com", content="reply from b"))
check("b->a reply success", SendResponse(**recv(conn_b)).is_succees)

conn_a.send(FetchRequest())
r = FetchResponse(**recv(conn_a))
check("a received reply from b", "reply from b" in r.messages)

# ---------------------------------------------------------------------------
# CREATE ITEM
# ---------------------------------------------------------------------------
print("\n=== Create item ===")

conn_a.send(CreateItemRequest(contents="plaintext_contents", auth_key=777777))
r = CreateItemResponse(**recv(conn_a))
check("create item: is_success=True", r.is_success)
check("create item: id is non-empty string", isinstance(r.id, str) and len(r.id) > 0)
item_id = r.id

# second item with different key
conn_a.send(CreateItemRequest(contents="other_contents", auth_key=888888))
r = CreateItemResponse(**recv(conn_a))
check("create second item success", r.is_success)
item_id_2 = r.id
check("two item IDs are distinct", item_id != item_id_2)

# ---------------------------------------------------------------------------
# ITEM REQUEST
# ---------------------------------------------------------------------------
print("\n=== Item request ===")

# non-existent UUID
conn_a.send(ItemRequest(id="00000000-0000-0000-0000-000000000000", auth_key=777777))
r = ItemResponse(**recv(conn_a))
check("non-existent item: is_success=False", not r.is_success)
check("non-existent item: wrong_key=False", not r.wrong_key)

# wrong key on real item
conn_a.send(ItemRequest(id=item_id, auth_key=1))
r = ItemResponse(**recv(conn_a))
check("wrong key: is_success=False", not r.is_success)
check("wrong key: wrong_key=True", r.wrong_key)

# correct key
conn_a.send(ItemRequest(id=item_id, auth_key=777777))
r = ItemResponse(**recv(conn_a))
check("item request: is_success=True", r.is_success)
check("item request: wrong_key=False", not r.wrong_key)
check("item request: contents correct", r.contents == "plaintext_contents")
check("item request: no release keys yet", r.release_key_contents == [])

# key for item 1 does not open item 2
conn_a.send(ItemRequest(id=item_id_2, auth_key=777777))
r = ItemResponse(**recv(conn_a))
check("item 1 key rejected for item 2", not r.is_success and r.wrong_key)

# ---------------------------------------------------------------------------
# ENCRYPT ITEM
# ---------------------------------------------------------------------------
print("\n=== Encrypt item ===")

# wrong key
conn_a.send(EncryptItemRequest(id=item_id, auth_key=1, public_key=rsa_pub_pem, prefix="PREFIX:"))
r = EncryptItemResponse(**recv(conn_a))
check("encrypt wrong key: is_success=False", not r.is_success)
check("encrypt wrong key: wrong_key=True", r.wrong_key)

# non-existent item
conn_a.send(EncryptItemRequest(id="00000000-0000-0000-0000-000000000000", auth_key=777777, public_key=rsa_pub_pem, prefix="PREFIX:"))
r = EncryptItemResponse(**recv(conn_a))
check("encrypt non-existent item: is_success=False", not r.is_success)
check("encrypt non-existent item: wrong_key=False", not r.wrong_key)

# correct encrypt
conn_a.send(EncryptItemRequest(id=item_id, auth_key=777777, public_key=rsa_pub_pem, prefix="PREFIX:"))
r = EncryptItemResponse(**recv(conn_a))
check("encrypt: is_success=True", r.is_success)
check("encrypt: wrong_key=False", not r.wrong_key)

# fetch item back and verify structure: starts with prefix, remainder decrypts correctly
conn_a.send(ItemRequest(id=item_id, auth_key=777777))
r = ItemResponse(**recv(conn_a))
check("encrypted item: is_success=True", r.is_success)
raw = r.contents.encode("latin-1")  # contents came back as str via latin-1, re-encode to bytes
check("encrypted item: starts with prefix", raw[:7] == b"PREFIX:")
decrypted = decrypt_item(raw[7:], rsa_priv)
check("encrypted item: decrypts back to original plaintext", decrypted == b"plaintext_contents")

# ---------------------------------------------------------------------------
# RELEASE ITEM
# ---------------------------------------------------------------------------
print("\n=== Release item ===")

# wrong key
conn_a.send(ReleaseItemRequest(id=item_id, auth_key=1, info="bad_release", expires=datetime(2027, 1, 1).isoformat()))
r = ReleaseItemResponse(**recv(conn_a))
check("release wrong key: is_success=False", not r.is_success)
check("release wrong key: wrong_key=True", r.wrong_key)

# non-existent item
conn_a.send(ReleaseItemRequest(id="00000000-0000-0000-0000-000000000000", auth_key=777777, info="x", expires=datetime(2027, 1, 1).isoformat()))
r = ReleaseItemResponse(**recv(conn_a))
check("release non-existent: is_success=False", not r.is_success)
check("release non-existent: wrong_key=False", not r.wrong_key)

# first release key
conn_a.send(ReleaseItemRequest(id=item_id, auth_key=777777, info="release_alpha", expires=datetime(2027, 6, 1).isoformat()))
r = ReleaseItemResponse(**recv(conn_a))
check("first release: is_success=True", r.is_success)
check("first release: wrong_key=False", not r.wrong_key)

conn_a.send(ItemRequest(id=item_id, auth_key=777777))
r = ItemResponse(**recv(conn_a))
check("after first release: exactly 1 release key", len(r.release_key_contents) == 1)
check("after first release: content correct", r.release_key_contents[0] == "release_alpha")

# second release key on same item
conn_a.send(ReleaseItemRequest(id=item_id, auth_key=777777, info="release_beta", expires=datetime(2028, 1, 1).isoformat()))
check("second release success", ReleaseItemResponse(**recv(conn_a)).is_success)

conn_a.send(ItemRequest(id=item_id, auth_key=777777))
r = ItemResponse(**recv(conn_a))
check("after second release: exactly 2 release keys", len(r.release_key_contents) == 2)
check("release keys in order: alpha first", r.release_key_contents[0] == "release_alpha")
check("release keys in order: beta second", r.release_key_contents[1] == "release_beta")

# release on item 2 — no bleed into item 1
conn_a.send(ReleaseItemRequest(id=item_id_2, auth_key=888888, info="item2_release", expires=datetime(2027, 3, 15).isoformat()))
check("item 2 release success", ReleaseItemResponse(**recv(conn_a)).is_success)

conn_a.send(ItemRequest(id=item_id, auth_key=777777))
r = ItemResponse(**recv(conn_a))
check("item 1 unaffected by item 2 release (still 2 keys)", len(r.release_key_contents) == 2)

conn_a.send(ItemRequest(id=item_id_2, auth_key=888888))
r = ItemResponse(**recv(conn_a))
check("item 2 has exactly 1 release key", len(r.release_key_contents) == 1)
check("item 2 release key content correct", r.release_key_contents[0] == "item2_release")

# ---------------------------------------------------------------------------
# done
# ---------------------------------------------------------------------------
stop_server.set()
listener.close()
shutil.rmtree(DATA_DIR, ignore_errors=True)
print(f"\n{passed} checks passed.")
print("All tests passed.")