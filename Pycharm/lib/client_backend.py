import os
import json
import threading
from uuid import UUID
from datetime import datetime
from typing import Callable, Any

from lib.socket_wrapper import try_connect_to_server, ClientConnection
from lib.request_response import (
    SignupRequest, SignupResponse,
    LoginRequest, LoginResponse,
    FetchRequest, FetchResponse,
    PushRequest,
    CreateItemRequest, CreateItemResponse,
    ItemRequest, ItemResponse,
    ReleaseItemRequest,
)

from lib.encryption import keypair, encrypt, decrypt, PublicKey, PrivateKey
from lib.hashing import hash_string


_connection_lock = threading.Lock()


class Task:
    def __init__(self):
        self._thread = None
        self._result = None
        self._done = False
        self._lock = threading.Lock()

    def start(self, fn: Callable, *args: Any):
        with self._lock:
            if self._thread and self._thread.is_alive():
                return

            self._result = None
            self._done = False

            def run():
                try:
                    self._result = fn(*args)
                except Exception:
                    self._result = "not connected"
                finally:
                    self._done = True

            self._thread = threading.Thread(target=run, daemon=True)
            self._thread.start()

    def is_pending(self) -> bool:
        return self._thread is not None and not self._done

    def get(self):
        return self._result

    def reset(self):
        self._thread = None
        self._result = None
        self._done = False


class ClientBackend:
    def __init__(self):
        self._conn: ClientConnection | None = None
        self._task = Task()

        self._email: str | None = None
        self._password: str | None = None

        self._private_key: PrivateKey | None = None
        self._public_key: PublicKey | None = None

        self._user_emails: list[str] | None = None
        self._user_descriptions: list[str] | None = None
        self._user_public_keys: list[PublicKey] | None = None

        self._private_info: dict | None = None

    def _connect(self) -> bool:
        if self._conn is not None:
            return True
        self._conn = try_connect_to_server()
        return self._conn is not None

    def _recv(self):
        msg = self._conn.recv()
        while msg is None:
            msg = self._conn.recv()
        return msg

    def _request(self, req):
        with _connection_lock:
            self._conn.send(req)
            return self._recv()

    def _encrypt_private_info(self) -> str:
        payload = {"items": (self._private_info or {}).get("items", {})}
        return encrypt(self._public_key, json.dumps(payload).encode()).hex()

    def _decrypt_private_info(self, raw: str) -> dict:
        try:
            data = decrypt(self._private_key, bytes.fromhex(raw))
            return json.loads(data.decode())
        except Exception:
            return {"items": {}}

    def _fetch(self):
        raw = self._request(FetchRequest())
        r = FetchResponse(**raw)

        if not r.is_success:
            return "error"

        self._user_emails = r.user_emails
        self._user_descriptions = r.user_descriptions
        self._user_public_keys = r.user_public_keys

        if self._private_key:
            self._private_info = self._decrypt_private_info(r.private_info)

        return "done"

    def fetch_from_server(self):
        if self._task.is_pending():
            return "wait"

        res = self._task.get()
        if res is not None:
            self._task.reset()
            return res

        if not self._connect():
            return "not connected"

        self._task.start(self._fetch)
        return "wait"

    def _login_task(self, email: str, password: str):
        try:
            auth_key: str = hash_string(password)

            raw = self._request(LoginRequest(email=email, auth_key=auth_key))
            r = LoginResponse(**raw)

            if not r.is_success:
                return "wrong password" if r.incorrect_password else "error"

            self._email = email
            self._password = password
            self._private_key, self._public_key = keypair(password)

            return self._fetch()

        except Exception:
            self._conn = None
            return "not connected"

    def login(self, email: str, password: str):
        if self._email == email and self._private_key is not None:
            return "done"

        if self._task.is_pending():
            return "wait"

        res = self._task.get()
        if res is not None:
            self._task.reset()
            return res

        if not self._connect():
            return "not connected"

        self._task.start(self._login_task, email, password)
        return "wait"

    def _signup_task(self, email: str, password: str, desc: str):
        try:
            priv, pub = keypair(password)

            self._private_key = priv
            self._public_key = pub
            self._email = email
            self._password = password

            self._private_info = {"items": {}}

            encrypted = encrypt(pub, json.dumps({"items": {}}).encode()).hex()

            auth_key: str = hash_string(password)

            raw = self._request(SignupRequest(
                email=email,
                auth_key=auth_key,
                private_info=encrypted,
                public_key=pub,
            ))

            r = SignupResponse(**raw)

            if not r.is_success:
                return "exists" if r.email_is_taken else "error"

            return self._fetch()

        except Exception:
            self._conn = None
            return "not connected"

    def signup(self, email: str, password: str, desc: str):
        if self._task.is_pending():
            return "wait"

        res = self._task.get()
        if res is not None:
            self._task.reset()
            return res

        if not self._connect():
            return "not connected"

        self._task.start(self._signup_task, email, password, desc)
        return "wait"

    def _items(self):
        return (self._private_info or {}).get("items", {})

    def create_item(self, name: str, data: bytes):
        if self._email is None:
            return "not logged in"

        if self._task.is_pending():
            return "wait"

        res = self._task.get()
        if res is not None:
            self._task.reset()
            return res

        if not self._connect():
            return "not connected"

        self._task.start(self._create_item_task, name, data)
        return "wait"

    def _create_item_task(self, name: str, data: bytes):
        try:
            auth_key: str = hash_string(self._password)

            raw = self._request(CreateItemRequest(
                contents=data.hex(),
                auth_key=auth_key,
            ))

            r = CreateItemResponse(**raw)

            if not r.is_success:
                return "error"

            items = self._items()
            items[r.id] = {
                "name": name,
                "auth_key": auth_key,
                "size": len(data),
                "locked": True,
                "released": False,
            }

            self._push()
            return r.id

        except Exception:
            self._conn = None
            return "not connected"

    def _push(self):
        encoded = self._encrypt_private_info()
        with _connection_lock:
            self._conn.send(PushRequest(private_info=encoded, messages=[]))
            self._recv()

    def read_item(self, item_id: UUID):
        if self._email is None:
            return "not logged in"

        if self._task.is_pending():
            return "wait"

        res = self._task.get()
        if res is not None:
            self._task.reset()
            return res

        if not self._connect():
            return "not connected"

        self._task.start(self._read_task, item_id)
        return "wait"

    def _read_task(self, item_id: UUID):
        try:
            items = self._items()
            if str(item_id) not in items:
                return "doesnt exist"

            entry = items[str(item_id)]

            raw = self._request(ItemRequest(
                id=str(item_id),
                auth_key=entry["auth_key"],
            ))

            r = ItemResponse(**raw)

            if not r.is_success:
                return "corrupt"

            if r.release_key_contents:
                return bytes.fromhex(r.release_key_contents[-1])

            return bytes.fromhex(r.contents)

        except Exception:
            self._conn = None
            return "not connected"

    def release_item(self, item_id: UUID, until: datetime):
        if self._email is None:
            return "not logged in"

        if self._task.is_pending():
            return "wait"

        res = self._task.get()
        if res is not None:
            self._task.reset()
            return res

        if not self._connect():
            return "not connected"

        self._task.start(self._release_task, item_id, until)
        return "wait"

    def _release_task(self, item_id: UUID, until: datetime):
        try:
            items = self._items()
            if str(item_id) not in items:
                return "doesnt exist"

            entry = items[str(item_id)]

            raw = self._request(ItemRequest(
                id=str(item_id),
                auth_key=entry["auth_key"],
            ))

            r = ItemResponse(**raw)

            plaintext = bytes.fromhex(r.contents)

            self._request(ReleaseItemRequest(
                id=str(item_id),
                auth_key=entry["auth_key"],
                info=plaintext.hex(),
                expires=until.isoformat(),
            ))

            entry["released"] = True
            self._push()

            return "done"

        except Exception:
            self._conn = None
            return "not connected"
