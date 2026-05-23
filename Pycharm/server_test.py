"""
Integration test — harder edition.

Three users (a, b, c). Every mutation is verified by reading back state.
Every failure path is checked for the exact right error flag.
Requests without login are tested. Multiple items, multiple release keys.
"""

import shutil
import threading
from pathlib import Path
from time import sleep
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

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
failed = 0

def check(label: str, condition: bool):
    global passed, failed
    if not condition:
        failed += 1
        print(f"  FAIL  {label}")
        raise AssertionError(label)
    passed += 1
    print(f"  PASS  {label}")

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

# ---------------------------------------------------------------------------
# connect three clients plus one anonymous connection
# ---------------------------------------------------------------------------

def connect():
    c = try_connect_to_server()
    while c is None:
        c = try_connect_to_server()
    return c

conn_a = connect()
conn_b = connect()
conn_c = connect()
conn_anon = connect()  # never logs in — used to test auth failures

print("All clients connected. Starting tests...\n")

# ---------------------------------------------------------------------------
# 1. Signup
# ---------------------------------------------------------------------------
print("=== Signup ===")

conn_a.send(SignupRequest(email="usera@test.com", auth_key=111111, private_info="priv_a", public_key=222222))
r = SignupResponse(**recv(conn_a))
check("user_a signup succeeds", r.is_succees and not r.email_is_taken)

conn_b.send(SignupRequest(email="userb@test.com", auth_key=333333, private_info="priv_b", public_key=444444))
r = SignupResponse(**recv(conn_b))
check("user_b signup succeeds", r.is_succees and not r.email_is_taken)

conn_c.send(SignupRequest(email="userc@test.com", auth_key=555555, private_info="priv_c", public_key=666666))
r = SignupResponse(**recv(conn_c))
check("user_c signup succeeds", r.is_succees and not r.email_is_taken)

# duplicate email — same connection
conn_a.send(SignupRequest(email="usera@test.com", auth_key=999999, private_info="x", public_key=1))
r = SignupResponse(**recv(conn_a))
check("duplicate email: is_succees=False", not r.is_succees)
check("duplicate email: email_is_taken=True", r.email_is_taken)

# duplicate email — different connection
conn_b.send(SignupRequest(email="usera@test.com", auth_key=111111, private_info="x", public_key=1))
r = SignupResponse(**recv(conn_b))
check("duplicate email from different connection rejected", not r.is_succees and r.email_is_taken)

# invalid email format
conn_a.send(SignupRequest(email="not-an-email", auth_key=111111, private_info="x", public_key=1))
r = SignupResponse(**recv(conn_a))
check("invalid email format rejected", not r.is_succees)

# ---------------------------------------------------------------------------
# 2. Login
# ---------------------------------------------------------------------------
print("\n=== Login ===")

# wrong password
conn_a.send(LoginRequest(email="usera@test.com", auth_key=999999))
r = LoginResponse(**recv(conn_a))
check("wrong password: is_succees=False", not r.is_succees)
check("wrong password: incorrect_password=True", r.incorrect_password)
check("wrong password: user_doesnt_exist=False", not r.user_doesnt_exist)

# non-existent user
conn_a.send(LoginRequest(email="ghost@test.com", auth_key=111111))
r = LoginResponse(**recv(conn_a))
check("unknown user: is_succees=False", not r.is_succees)
check("unknown user: user_doesnt_exist=True", r.user_doesnt_exist)
check("unknown user: incorrect_password=False", not r.incorrect_password)

# correct logins
conn_a.send(LoginRequest(email="usera@test.com", auth_key=111111))
check("user_a login", LoginResponse(**recv(conn_a)).is_succees)

conn_b.send(LoginRequest(email="userb@test.com", auth_key=333333))
check("user_b login", LoginResponse(**recv(conn_b)).is_succees)

conn_c.send(LoginRequest(email="userc@test.com", auth_key=555555))
check("user_c login", LoginResponse(**recv(conn_c)).is_succees)

# ---------------------------------------------------------------------------
# 3. Fetch (auth checks + content)
# ---------------------------------------------------------------------------
print("\n=== Fetch ===")

conn_anon.send(FetchRequest())
r = FetchResponse(**recv(conn_anon))
check("fetch without login: is_success=False", not r.is_success)
check("fetch without login: isnt_logged_in=True", r.isnt_logged_in)

conn_a.send(FetchRequest())
r = FetchResponse(**recv(conn_a))
check("fetch succeeds for user_a", r.is_success)
check("all three users visible", all(e in r.user_emails for e in ["usera@test.com", "userb@test.com", "userc@test.com"]))
check("private_info correct", r.private_info == "priv_a")
check("no messages yet", r.messages == [])

idx_a = r.user_emails.index("usera@test.com")
idx_b = r.user_emails.index("userb@test.com")
check("user_a public key correct in fetch", r.user_public_keys[idx_a] == str(222222))
check("user_b public key correct in fetch", r.user_public_keys[idx_b] == str(444444))

# ---------------------------------------------------------------------------
# 4. Push
# ---------------------------------------------------------------------------
print("\n=== Push ===")

conn_anon.send(PushRequest(private_info="hacked", messages=[]))
r = PushResponse(**recv(conn_anon))
check("push without login: is_succees=False", not r.is_succees)
check("push without login: isnt_logged_in=True", r.isnt_logged_in)

conn_a.send(PushRequest(private_info="updated_priv_a", messages=["msg1", "msg2"]))
check("push succeeds", PushResponse(**recv(conn_a)).is_succees)

conn_a.send(FetchRequest())
r = FetchResponse(**recv(conn_a))
check("private_info updated", r.private_info == "updated_priv_a")
check("messages updated", r.messages == ["msg1", "msg2"])

# push again, clearing messages
conn_a.send(PushRequest(private_info="updated_priv_a", messages=[]))
check("second push succeeds", PushResponse(**recv(conn_a)).is_succees)

conn_a.send(FetchRequest())
r = FetchResponse(**recv(conn_a))
check("messages cleared after second push", r.messages == [])

# ---------------------------------------------------------------------------
# 5. Send
# ---------------------------------------------------------------------------
print("\n=== Send ===")

conn_anon.send(SendRequest(target_email="usera@test.com", content="spam"))
r = SendResponse(**recv(conn_anon))
check("send without login: is_succees=False", not r.is_succees)
check("send without login: not_logged_in=True", r.not_logged_in)

conn_a.send(SendRequest(target_email="nobody@test.com", content="hello"))
r = SendResponse(**recv(conn_a))
check("send to unknown user: is_succees=False", not r.is_succees)
check("send to unknown user: user_doesnt_exist=True", r.user_doesnt_exist)
check("send to unknown user: invalid_email=False", not r.invalid_email)

conn_a.send(SendRequest(target_email="not-an-email", content="hello"))
r = SendResponse(**recv(conn_a))
check("send to invalid email: is_succees=False", not r.is_succees)
check("send to invalid email: invalid_email=True", r.invalid_email)

conn_a.send(SendRequest(target_email="userb@test.com", content="hey b, message 1"))
check("a->b message 1", SendResponse(**recv(conn_a)).is_succees)

conn_a.send(SendRequest(target_email="userb@test.com", content="hey b, message 2"))
check("a->b message 2", SendResponse(**recv(conn_a)).is_succees)

conn_a.send(SendRequest(target_email="userc@test.com", content="hey c"))
check("a->c message", SendResponse(**recv(conn_a)).is_succees)

conn_b.send(FetchRequest())
r = FetchResponse(**recv(conn_b))
check("b received exactly 2 messages", len(r.messages) == 2)
check("b message 1 correct", r.messages[0] == "hey b, message 1")
check("b message 2 correct", r.messages[1] == "hey b, message 2")

conn_c.send(FetchRequest())
r = FetchResponse(**recv(conn_c))
check("c received exactly 1 message", len(r.messages) == 1)
check("c message correct", r.messages[0] == "hey c")

conn_b.send(SendRequest(target_email="usera@test.com", content="hey a back"))
check("b->a reply", SendResponse(**recv(conn_b)).is_succees)

conn_a.send(FetchRequest())
r = FetchResponse(**recv(conn_a))
check("a received reply from b", "hey a back" in r.messages)

# ---------------------------------------------------------------------------
# 6. Create items
# ---------------------------------------------------------------------------
print("\n=== Create items ===")

conn_a.send(CreateItemRequest(contents="item_one_contents", auth_key=777777))
r = CreateItemResponse(**recv(conn_a))
check("item 1 created", r.is_success and r.id != "")
item_id_1 = r.id

conn_a.send(CreateItemRequest(contents="item_two_contents", auth_key=888888))
r = CreateItemResponse(**recv(conn_a))
check("item 2 created", r.is_success)
item_id_2 = r.id

conn_b.send(CreateItemRequest(contents="b_item_contents", auth_key=999111))
r = CreateItemResponse(**recv(conn_b))
check("b item created", r.is_success)
item_id_b = r.id

check("all item IDs are distinct", len({item_id_1, item_id_2, item_id_b}) == 3)

# ---------------------------------------------------------------------------
# 7. Item request
# ---------------------------------------------------------------------------
print("\n=== Item request ===")

conn_a.send(ItemRequest(id="00000000-0000-0000-0000-000000000000", auth_key=777777))
r = ItemResponse(**recv(conn_a))
check("non-existent item: is_success=False", not r.is_success)
check("non-existent item: wrong_key=False (unknown error, not auth)", not r.wrong_key)

conn_a.send(ItemRequest(id=item_id_1, auth_key=1))
r = ItemResponse(**recv(conn_a))
check("wrong key: is_success=False", not r.is_success)
check("wrong key: wrong_key=True", r.wrong_key)

conn_a.send(ItemRequest(id=item_id_1, auth_key=777777))
r = ItemResponse(**recv(conn_a))
check("item 1 fetch succeeds", r.is_success)
check("item 1 contents correct", r.contents == "item_one_contents")
check("item 1 no release keys yet", r.release_key_contents == [])

conn_a.send(ItemRequest(id=item_id_2, auth_key=888888))
r = ItemResponse(**recv(conn_a))
check("item 2 fetch succeeds", r.is_success)
check("item 2 contents correct", r.contents == "item_two_contents")

conn_b.send(ItemRequest(id=item_id_b, auth_key=999111))
r = ItemResponse(**recv(conn_b))
check("b item fetch succeeds", r.is_success)
check("b item contents correct", r.contents == "b_item_contents")

# item 1 key must not open item 2
conn_a.send(ItemRequest(id=item_id_2, auth_key=777777))
r = ItemResponse(**recv(conn_a))
check("item 1 key rejected for item 2", not r.is_success and r.wrong_key)

# b key must not open a's item
conn_b.send(ItemRequest(id=item_id_1, auth_key=999111))
r = ItemResponse(**recv(conn_b))
check("b key rejected for a's item", not r.is_success and r.wrong_key)

# ---------------------------------------------------------------------------
# 8. Release item
# ---------------------------------------------------------------------------
print("\n=== Release item ===")

conn_a.send(ReleaseItemRequest(id=item_id_1, auth_key=1, info="fake", expires=datetime(2027, 1, 1).isoformat()))
r = ReleaseItemResponse(**recv(conn_a))
check("release with wrong key: is_success=False", not r.is_success)
check("release with wrong key: wrong_key=True", r.wrong_key)

conn_a.send(ReleaseItemRequest(id=item_id_1, auth_key=777777, info="release_alpha", expires=datetime(2027, 6, 1).isoformat()))
check("first release key stored", ReleaseItemResponse(**recv(conn_a)).is_success)

conn_a.send(ItemRequest(id=item_id_1, auth_key=777777))
r = ItemResponse(**recv(conn_a))
check("one release key present", len(r.release_key_contents) == 1)
check("release key content correct", r.release_key_contents[0] == "release_alpha")

conn_a.send(ReleaseItemRequest(id=item_id_1, auth_key=777777, info="release_beta", expires=datetime(2028, 1, 1).isoformat()))
check("second release key stored", ReleaseItemResponse(**recv(conn_a)).is_success)

conn_a.send(ItemRequest(id=item_id_1, auth_key=777777))
r = ItemResponse(**recv(conn_a))
check("two release keys present", len(r.release_key_contents) == 2)
check("release keys in order: alpha first", r.release_key_contents[0] == "release_alpha")
check("release keys in order: beta second", r.release_key_contents[1] == "release_beta")

# release key on item 2 — no bleed into item 1
conn_a.send(ReleaseItemRequest(id=item_id_2, auth_key=888888, info="item2_release", expires=datetime(2027, 3, 15).isoformat()))
check("item 2 release key stored", ReleaseItemResponse(**recv(conn_a)).is_success)

conn_a.send(ItemRequest(id=item_id_1, auth_key=777777))
r = ItemResponse(**recv(conn_a))
check("item 1 still has exactly 2 release keys (no bleed)", len(r.release_key_contents) == 2)

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
print(f"\n{passed} passed, {failed} failed.")
if failed == 0:
    print("All tests passed.")