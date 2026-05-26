import os
import json
import hashlib
import threading
from uuid import UUID as Uuid, uuid4
from datetime import datetime
from typing import Literal, Callable, Any

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPublicKey,
    RSAPrivateKey,
)

from lib.email import Email
from lib.socket_wrapper import try_connect_to_server, ClientConnection
from lib.request_response import (
    SignupRequest, SignupResponse,
    LoginRequest, LoginResponse,
    FetchRequest, FetchResponse,
    PushRequest, PushResponse, SendResponse,
    CreateItemRequest, CreateItemResponse,
    ItemRequest, ItemResponse,
    EncryptItemRequest, EncryptItemResponse,
    ReleaseItemRequest, ReleaseItemResponse,
    SendRequest,
)

# ---------------------------------------------------------------------------
# background task helper
# ---------------------------------------------------------------------------

_TASK_LOCK = threading.Lock()


class Task:
    def __init__(self, fn: Callable, *args: Any):
        self._result: Any = None
        self._exception: Exception | None = None

        self._is_running = True
        self._has_failed = False
        self._has_succeeded = False

        def run():
            try:
                with _TASK_LOCK:
                    self._result = fn(*args)

                self._has_succeeded = True
            except Exception as e:
                self._exception = e
                self._has_failed = True
            finally:
                self._is_running = False

        self._thread = threading.Thread(target=run, daemon=True)
        self._thread.start()

    def is_running(self) -> bool:
        return self._is_running

    def has_failed(self) -> bool:
        return self._has_failed

    def has_succeeded(self) -> bool:
        return self._has_succeeded

    def result(self) -> Any:
        return self._result

    def exception(self) -> Exception | None:
        return self._exception

# ---------------------------------------------------------------------------
# ClientBackend
# ---------------------------------------------------------------------------


class ClientBackend:
    # state
    _conn: ClientConnection | None
    _task: Task | None

    # global info
    _global_user_emails: list[str] | None
    _global_user_descriptions: list[str] | None
    _global_user_pub_keys: list[RSAPublicKey] | None

    # login info
    _email: Email | None
    _password: str | None

    # private info
    _priv_key: RSAPrivateKey | None
    _item_ids: list[int]
    _item_names: list[str]
    _item_auth_keys: list[int]
    _item_locked: list[bool | None]
    _item_sizes: list[int]
    _item_release_until: list[str | None]

    # invitations
    _invitation_ids: list[int]
    _invitation_names: list[str]
    _invitation_auth_keys: list[int]

    def __init__(self):
        # connection
        self._conn = None
        self._task = None

        # auth state
        self._email: str | None = None
        self._password: str | None = None  # kept in memory for private_info decryption
        self._priv_key = None              # RSA private key object
        self._pub_key = None               # RSA public key object

        # cached fetch data
        self._fetched_private_info: dict | None = None  # parsed private_info JSON
        self._global_user_emails: list[str] | None = None
        self._global_user_descriptions: list[str] | None = None
        self._global_user_pub_keys: list[str] | None = None

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------


    def _derive_key_from_password(self, password: str) -> bytes:
        """Derive a 32-byte AES key from a password using scrypt."""
        return hashlib.scrypt(
            password=password.encode("utf-8"),
            salt=b"i-hate-school",
            n=2 ** 14, r=8, p=1, dklen=32,
        )


    def _serialize_pub_key(self, pub_key: RSAPublicKey) -> str:
        return pub_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")


    def _deserialize_pub_key(self, pem: str) -> RSAPublicKey:
        return serialization.load_pem_public_key(pem.encode("utf-8"))


    def _serialize_priv_key(self, priv_key: RSAPrivateKey) -> str:
        return priv_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode("utf-8")


    def _deserialize_priv_key(self, pem: str) -> RSAPrivateKey:
        return serialization.load_pem_private_key(pem.encode("utf-8"), password=None)


    def _user_pub_key(self, email: str) -> RSAPublicKey | None:
        if self._global_user_emails is None:
            return None

        try:
            idx = self._global_user_emails.index(email)
        except ValueError:
            return None

        serialized_pub_key = self._global_user_pub_keys[idx]
        return self._deserialize_pub_key(serialized_pub_key)

    # ------------------------------------------------------------------
    # connection
    # ------------------------------------------------------------------

    def _ensure_server_connection(self) -> bool:
        if self._conn is not None:
            return True
        self._conn = try_connect_to_server()
        return self._conn is not None

    def _recv_from_server(self):
        result = self._conn.recv()
        while result is None:
            result = self._conn.recv()
        return result

    # ------------------------------------------------------------------
    # private_info encode/decode
    # ------------------------------------------------------------------

    def _serialize_and_encrypt_priv_info(self) -> str:
        private_key = self._derive_key_from_password(self._password)
        payload = {
            "private_key": private_key,
            "items": self._fetched_private_info.get("items", {}),
        }
        return json.dumps(payload)

    def _decrypt_and_deserialize_priv_info(self, raw: str) -> dict | None:
        """Decrypt and parse private_info str. Returns None on failure."""
        try:
            payload = json.loads(raw)
            aes_key = _derive_key_from_password(self._password)
            priv_pem = _decrypt_private_key(payload["priv_key_pem_hex"], aes_key)
            self._priv_key = _deserialize_priv_key(priv_pem)
            self._pub_key = self._priv_key.public_key()
            return payload
        except Exception:
            return None

    # ------------------------------------------------------------------
    # fetch_from_server
    # ------------------------------------------------------------------

    def fetch_from_server(self) -> Literal["wait", "not connected", "done", "unknown server error"]:
        if self._task.is_pending():
            if not self._ensure_server_connection():
                return "not connected"
            self._task_kind = "fetch"
            self._task.start(self._do_fetch)
            return "wait"

        result = self._task.get()
        if result is _TASK_RUNNING:
            return "wait"

        self._task.reset()
        return result  # "done", "not connected", "unknown server error"

    def _do_fetch(self):
        try:
            self._conn.send(FetchRequest())
            r = FetchResponse(**self._recv_from_server())
            if not r.is_success:
                return "unknown server error"

            self._global_user_emails = r.user_emails
            self._global_user_descriptions = r.user_descriptions
            self._global_user_pub_keys = r.user_public_keys

            # decode private_info if logged in
            if self._email is not None and self._password is not None:
                parsed = self._decrypt_and_deserialize_priv_info(r.private_info)
                if parsed is not None:
                    self._fetched_private_info = parsed

            return "done"
        except Exception:
            self._conn = None
            return "not connected"

    # ------------------------------------------------------------------
    # global_user_emails / global_user_description
    # ------------------------------------------------------------------

    def global_user_emails(self) -> list[str] | Literal["havent fetched"]:
        if self._global_user_emails is None:
            return "havent fetched"
        return self._global_user_emails

    def global_user_description(self, email: str) -> str | Literal["havent fetched", "doesnt exist"]:
        if self._global_user_emails is None:
            return "havent fetched"
        try:
            idx = self._global_user_emails.index(email)
        except ValueError:
            return "doesnt exist"
        return self._global_user_descriptions[idx]

    # ------------------------------------------------------------------
    # login
    # ------------------------------------------------------------------

    def login(self, email: str, password: str) -> Literal["wait", "done", "not connected", "wrong password", "unknown server error"]:
        # already logged in as this email (fetch already succeeded)
        if self._email == email and self._fetched_private_info is not None:
            return "done"

        if self._task.is_pending():
            if not self._ensure_server_connection():
                return "not connected"
            self._task_kind = "login"
            self._task.start(self._do_login, email, password)
            return "wait"

        result = self._task.get()
        if result is _TASK_RUNNING:
            return "wait"

        self._task.reset()
        return result

    def _do_login(self, email: str, password: str):
        try:
            auth_key = int.from_bytes(
                hashlib.scrypt(password.encode(), salt=b"auth-key-salt",
                               n=2**14, r=8, p=1, dklen=32)
            )
            self._conn.send(LoginRequest(email=email, auth_key=auth_key))
            r = LoginResponse(**self._recv_from_server())
            if not r.is_succees:
                if r.incorrect_password:
                    return "wrong password"
                return "unknown server error"

            self._email = email
            self._password = password

            # fetch to load private_info and RSA key
            self._conn.send(FetchRequest())
            fr = FetchResponse(**self._recv_from_server())
            if not fr.is_success:
                return "unknown server error"

            self._global_user_emails = fr.user_emails
            self._global_user_descriptions = fr.user_descriptions
            self._global_user_pub_keys = fr.user_public_keys

            parsed = self._decrypt_and_deserialize_priv_info(fr.private_info)
            if parsed is None:
                return "unknown server error"
            self._fetched_private_info = parsed
            return "done"
        except Exception:
            self._conn = None
            return "not connected"

    # ------------------------------------------------------------------
    # signup
    # ------------------------------------------------------------------

    def signup(self, email: str, password: str, description: str) -> Literal[
        "wait", "done", "already exists", "invalid password", "not connected", "unknown server error"
    ]:
        if self._email == email and self._fetched_private_info is not None:
            return "done"

        if self._task.is_pending():
            if not self._ensure_server_connection():
                return "not connected"
            self._task_kind = "signup"
            self._task.start(self._do_signup, email, password, description)
            return "wait"

        result = self._task.get()
        if result is _TASK_RUNNING:
            return "wait"

        self._task.reset()
        return result

    def _do_signup(self, email: str, password: str, description: str):
        try:
            # derive auth key from password
            auth_key = int.from_bytes(
                hashlib.scrypt(password.encode(), salt=b"auth-key-salt",
                               n=2**14, r=8, p=1, dklen=32)
            )

            # generate RSA key pair
            priv_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            pub_key = priv_key.public_key()
            pub_pem = _serialize_pub_key(pub_key)

            # build initial private_info
            aes_key = _derive_key_from_password(password)
            priv_pem = _serialize_priv_key(priv_key)
            encrypted_hex = _encrypt_private_key(priv_pem, aes_key)
            private_info_str = json.dumps({
                "priv_key_pem_hex": encrypted_hex,
                "items": {},
            })

            self._conn.send(SignupRequest(
                email=email,
                auth_key=auth_key,
                private_info=private_info_str,
                public_key=pub_pem,
            ))
            r = SignupResponse(**self._recv_from_server())
            if not r.is_succees:
                if r.email_is_taken:
                    return "already exists"
                return "unknown server error"

            self._email = email
            self._password = password
            self._priv_key = priv_key
            self._pub_key = pub_key
            self._fetched_private_info = {"priv_key_pem_hex": encrypted_hex, "items": {}}

            # fetch to populate user list
            self._conn.send(FetchRequest())
            fr = FetchResponse(**self._recv_from_server())
            if fr.is_success:
                self._global_user_emails = fr.user_emails
                self._global_user_descriptions = fr.user_descriptions
                self._global_user_pub_keys = fr.user_public_keys

            return "done"
        except Exception as e:
            self._conn = None
            return "not connected"

    # ------------------------------------------------------------------
    # logged_into_email
    # ------------------------------------------------------------------

    def logged_into_email(self) -> str | Literal["not logged in"]:
        if self._email is None:
            return "not logged in"
        return self._email

    # ------------------------------------------------------------------
    # item list accessors (immediate, no background)
    # ------------------------------------------------------------------

    def _items(self) -> dict | None:
        if self._fetched_private_info is None:
            return None
        return self._fetched_private_info.get("items", {})

    def my_item_ids(self) -> list[Uuid] | Literal["not logged in", "havent fetched"]:
        if self._email is None:
            return "not logged in"
        items = self._items()
        if items is None:
            return "havent fetched"
        return [Uuid(k) for k, v in items.items() if not v.get("is_invitation", False)]

    def my_item_invitation_ids(self) -> list[Uuid] | Literal["not logged in", "havent fetched"]:
        if self._email is None:
            return "not logged in"
        items = self._items()
        if items is None:
            return "havent fetched"
        return [Uuid(k) for k, v in items.items() if v.get("is_invitation", False)]

    def item_name(self, id: Uuid) -> str | Literal["not logged in", "havent fetched", "doesnt exist"]:
        if self._email is None:
            return "not logged in"
        items = self._items()
        if items is None:
            return "havent fetched"
        entry = items.get(str(id))
        if entry is None:
            return "doesnt exist"
        return entry.get("name", "unknown")

    def item_encryption_method(self, id: Uuid) -> str | Literal["not logged in", "havent fetched", "doesnt exist"]:
        if self._email is None:
            return "not logged in"
        items = self._items()
        if items is None:
            return "havent fetched"
        if str(id) not in items:
            return "doesnt exist"
        return "AES-256-GCM"

    def item_size(self, id: Uuid) -> int | Literal["not logged in", "havent fetched", "doesnt exist"]:
        if self._email is None:
            return "not logged in"
        items = self._items()
        if items is None:
            return "havent fetched"
        entry = items.get(str(id))
        if entry is None:
            return "doesnt exist"
        return entry.get("size", 0)

    def item_is_locked(self, id: Uuid) -> bool | Literal["not logged in", "havent fetched", "doesnt exist", "corrupt"]:
        if self._email is None:
            return "not logged in"
        items = self._items()
        if items is None:
            return "havent fetched"
        if str(id) not in items:
            return "doesnt exist"
        # we determine lock status when we read — default to locked
        return items.get(str(id), {}).get("locked", True)

    def has_released_item(self, id: Uuid) -> bool | Literal["not logged in", "havent fetched", "doesnt exist", "corrupt"]:
        if self._email is None:
            return "not logged in"
        items = self._items()
        if items is None:
            return "havent fetched"
        if str(id) not in items:
            return "doesnt exist"
        return items.get(str(id), {}).get("released", False)

    def released_item_timelimit(self, id: Uuid) -> datetime | Literal["not logged in", "havent fetched", "doesnt exist", "corrupt", "havent released"]:
        if self._email is None:
            return "not logged in"
        items = self._items()
        if items is None:
            return "havent fetched"
        if str(id) not in items:
            return "doesnt exist"
        ts = items.get(str(id), {}).get("release_until")
        if ts is None:
            return "havent released"
        return datetime.fromisoformat(ts)

    # ------------------------------------------------------------------
    # _auth_key_for_item: derive AES key bytes from item auth_key int
    # ------------------------------------------------------------------

    def _item_aes_key(self, auth_key: int) -> bytes:
        return auth_key.to_bytes(32, "big")

    def _aes_encrypt(self, data: bytes, auth_key: int) -> bytes:
        key = self._item_aes_key(auth_key)
        nonce = os.urandom(12)
        return nonce + AESGCM(key).encrypt(nonce, data, None)

    def _aes_decrypt(self, blob: bytes, auth_key: int) -> bytes:
        key = self._item_aes_key(auth_key)
        nonce, ciphertext = blob[:12], blob[12:]
        return AESGCM(key).decrypt(nonce, ciphertext, None)

    # ------------------------------------------------------------------
    # _push_private_info: persist our local state back to the server
    # ------------------------------------------------------------------

    def _push_private_info(self):
        """Synchronously push private_info to the server. Call from background threads only."""
        encoded = self._serialize_and_encrypt_priv_info()
        self._conn.send(PushRequest(private_info=encoded, messages=[]))
        self._recv_from_server()  # consume PushResponse

    # ------------------------------------------------------------------
    # create_item
    # ------------------------------------------------------------------

    def create_item(self, name: str, data: bytes) -> Literal[
        "wait", "done", "not logged in", "corrupt", "not connected", "unknown server error"
    ]:
        if self._email is None:
            return "not logged in"

        if self._task.is_pending():
            if not self._ensure_server_connection():
                return "not connected"
            self._task_kind = "create_item"
            self._task.start(self._do_create_item, name, data)
            return "wait"

        result = self._task.get()
        if result is _TASK_RUNNING:
            return "wait"

        self._task.reset()
        return result

    def _do_create_item(self, name: str, data: bytes):
        try:
            # generate a random 256-bit auth key (must fit in 32 bytes unsigned)
            auth_key_bytes = os.urandom(31)  # 31 bytes = 248 bits, safely under 256-bit limit
            auth_key = int.from_bytes(auth_key_bytes, "big")

            # encrypt data with AES derived from auth_key
            encrypted = self._aes_encrypt(data, auth_key)
            contents_str = encrypted.hex()

            self._conn.send(CreateItemRequest(contents=contents_str, auth_key=auth_key))
            r = CreateItemResponse(**self._recv_from_server())
            if not r.is_success:
                return "unknown server error"

            item_id = r.id

            # store in private_info
            if self._fetched_private_info is None:
                self._fetched_private_info = {"items": {}}
            self._fetched_private_info["items"][item_id] = {
                "name": name,
                "auth_key": auth_key,
                "is_invitation": False,
                "released": False,
                "locked": True,
                "size": len(data),
            }
            self._push_private_info()
            return "done"
        except Exception:
            self._conn = None
            return "not connected"

    # ------------------------------------------------------------------
    # read_item
    # ------------------------------------------------------------------

    def read_item(self, id: Uuid) -> bytes | Literal[
        "wait", "not connected", "not logged in", "havent fetched",
        "doesnt exist", "locked", "corrupt", "unknown server error"
    ]:
        if self._email is None:
            return "not logged in"
        if self._fetched_private_info is None:
            return "havent fetched"

        if self._task.is_pending():
            if not self._ensure_server_connection():
                return "not connected"
            self._task_kind = "read_item"
            self._task.start(self._do_read_item, id)
            return "wait"

        result = self._task.get()
        if result is _TASK_RUNNING:
            return "wait"

        self._task.reset()
        return result

    def _do_read_item(self, id: Uuid):
        try:
            items = self._items()
            if items is None or str(id) not in items:
                return "doesnt exist"

            entry = items[str(id)]
            auth_key = entry["auth_key"]

            self._conn.send(ItemRequest(id=str(id), auth_key=auth_key))
            r = ItemResponse(**self._recv_from_server())
            if not r.is_success:
                return "corrupt"

            # if any release key exists, the data has been released -- use it
            if r.release_key_contents:
                # release key info is the plaintext stored as hex
                plaintext = bytes.fromhex(r.release_key_contents[-1])
                entry["locked"] = False
                return plaintext

            # otherwise decrypt the contents ourselves
            try:
                encrypted = bytes.fromhex(r.contents)
                plaintext = self._aes_decrypt(encrypted, auth_key)
                entry["locked"] = False
                return plaintext
            except Exception:
                entry["locked"] = True
                return "locked"

        except Exception:
            self._conn = None
            return "not connected"

    # ------------------------------------------------------------------
    # release_item
    # ------------------------------------------------------------------

    def release_item(self, id: Uuid, until: datetime) -> Literal[
        "wait", "done", "not logged in", "havent fetched",
        "doesnt exist", "corrupt", "havent joined", "unknown server error"
    ]:
        if self._email is None:
            return "not logged in"
        if self._fetched_private_info is None:
            return "havent fetched"

        if self._task.is_pending():
            if not self._ensure_server_connection():
                return "unknown server error"
            self._task_kind = "release_item"
            self._task.start(self._do_release_item, id, until)
            return "wait"

        result = self._task.get()
        if result is _TASK_RUNNING:
            return "wait"

        self._task.reset()
        return result

    def _do_release_item(self, id: Uuid, until: datetime):
        try:
            items = self._items()
            if items is None or str(id) not in items:
                return "doesnt exist"

            entry = items[str(id)]
            if entry.get("is_invitation", False):
                return "havent joined"

            auth_key = entry["auth_key"]

            # fetch item to get current contents
            self._conn.send(ItemRequest(id=str(id), auth_key=auth_key))
            r = ItemResponse(**self._recv_from_server())
            if not r.is_success:
                return "corrupt"

            # decrypt to get plaintext
            try:
                encrypted = bytes.fromhex(r.contents)
                plaintext = self._aes_decrypt(encrypted, auth_key)
            except Exception:
                return "corrupt"

            # store plaintext hex as the release key info
            self._conn.send(ReleaseItemRequest(
                id=str(id),
                auth_key=auth_key,
                info=plaintext.hex(),
                expires=until.isoformat(),
            ))
            rr = ReleaseItemResponse(**self._recv_from_server())
            if not rr.is_success:
                return "unknown server error"

            # update local state
            entry["released"] = True
            entry["release_until"] = until.isoformat()
            entry["locked"] = False
            self._push_private_info()
            return "done"
        except Exception:
            self._conn = None
            return "unknown server error"

    # ------------------------------------------------------------------
    # invite_user_to_item
    # ------------------------------------------------------------------

    def invite_user_to_item(self, user_email: str, item_id: Uuid) -> Literal[
        "wait", "done", "not logged in", "corrupt", "not connected",
        "item doesnt exist", "user doesnt exist", "unknown server error"
    ]:
        if self._email is None:
            return "not logged in"

        if self._task.is_pending():
            if not self._ensure_server_connection():
                return "not connected"
            self._task_kind = "invite"
            self._task.start(self._do_invite, user_email, item_id)
            return "wait"

        result = self._task.get()
        if result is _TASK_RUNNING:
            return "wait"

        self._task.reset()
        return result

    def _do_invite(self, user_email: str, item_id: Uuid):
        try:
            items = self._items()
            if items is None or str(item_id) not in items:
                return "item doesnt exist"

            target_pub_key = self._user_pub_key(user_email)
            if target_pub_key is None:
                return "user doesnt exist"

            entry = items[str(item_id)]

            invite_payload = json.dumps({
                "invite": True,
                "item_id": str(item_id),
                "auth_key": entry["auth_key"],
                "name": entry.get("name", "unknown"),
                "size": entry.get("size", 0),
            }).encode("utf-8")

            encrypted_payload = _rsa_encrypt(invite_payload, target_pub_key)

            self._conn.send(SendRequest(
                target_email=user_email,
                content=encrypted_payload.hex(),
            ))

            sr = SendResponse(**self._recv_from_server())

            if not sr.is_succees:
                if sr.user_doesnt_exist:
                    return "user doesnt exist"
                return "unknown server error"

            return "done"

        except Exception:
            self._conn = None
            return "not connected"

    # ------------------------------------------------------------------
    # join_item (process pending invitations from messages)
    # ------------------------------------------------------------------

    def _process_invite_messages(self):
        """
        Called after fetch: scan messages for invite payloads and add them
        to our items dict as is_invitation=True entries.
        """
        if self._fetched_private_info is None:
            return

        # We need to fetch messages -- they come in FetchResponse.messages
        # but we don't store them separately. Re-fetch here.
        try:
            self._conn.send(FetchRequest())
            fr = FetchResponse(**self._recv_from_server())
            if not fr.is_success:
                return

            self._global_user_emails = fr.user_emails
            self._global_user_descriptions = fr.user_descriptions
            self._global_user_pub_keys = fr.user_public_keys

            items = self._fetched_private_info.setdefault("items", {})
            changed = False
            remaining_messages = []

            for msg in fr.messages:
                try:
                    decrypted = _rsa_decrypt(bytes.fromhex(msg), self._priv_key)
                    payload = json.loads(decrypted.decode("utf-8"))

                    if payload.get("invite"):
                        item_id = payload["item_id"]

                        if item_id not in items:
                            items[item_id] = {
                                "name": payload["name"],
                                "auth_key": payload["auth_key"],
                                "is_invitation": True,
                                "released": False,
                                "locked": True,
                                "size": payload.get("size", 0),
                            }
                            changed = True

                        continue

                except Exception:
                    pass

                remaining_messages.append(msg)

            if changed:
                # push cleared messages + updated private_info
                encoded = self._serialize_and_encrypt_priv_info()
                self._conn.send(PushRequest(private_info=encoded, messages=remaining_messages))
                self._recv_from_server()
        except Exception:
            pass

    def join_item(self, id: Uuid) -> Literal[
        "wait", "done", "not logged in", "havent fetched",
        "doesnt exist", "corrupt", "unknown server error"
    ]:
        if self._email is None:
            return "not logged in"
        if self._fetched_private_info is None:
            return "havent fetched"

        if self._task.is_pending():
            if not self._ensure_server_connection():
                return "unknown server error"
            # first scan messages for invites if we haven't yet
            self._task_kind = "join_item"
            self._task.start(self._do_join_item, id)
            return "wait"

        result = self._task.get()
        if result is _TASK_RUNNING:
            return "wait"

        self._task.reset()
        return result

    def _do_join_item(self, id: Uuid):
        try:
            # scan for invite messages first
            self._process_invite_messages()

            items = self._items()
            if items is None or str(id) not in items:
                return "doesnt exist"

            entry = items[str(id)]
            if not entry.get("is_invitation", False):
                return "done"  # already joined

            auth_key = entry["auth_key"]

            # mark as joined (not invitation anymore)
            entry["is_invitation"] = False
            self._push_private_info()
            return "done"
        except Exception:
            self._conn = None
            return "unknown server error"

    # ------------------------------------------------------------------
    # reject_item
    # ------------------------------------------------------------------

    def reject_item(self, id: Uuid) -> Literal[
        "wait", "done", "not logged in", "havent fetched",
        "doesnt exist", "corrupt", "unknown server error"
    ]:
        if self._email is None:
            return "not logged in"
        if self._fetched_private_info is None:
            return "havent fetched"

        if self._task.is_pending():
            if not self._ensure_server_connection():
                return "unknown server error"
            self._task_kind = "reject_item"
            self._task.start(self._do_reject_item, id)
            return "wait"

        result = self._task.get()
        if result is _TASK_RUNNING:
            return "wait"

        self._task.reset()
        return result

    def _do_reject_item(self, id: Uuid):
        try:
            items = self._items()
            if items is None or str(id) not in items:
                return "doesnt exist"
            del items[str(id)]
            self._push_private_info()
            return "done"
        except Exception:
            self._conn = None
            return "unknown server error"

    # ------------------------------------------------------------------
    # delete_item
    # ------------------------------------------------------------------

    def delete_item(self, id: Uuid) -> Literal[
        "wait", "done", "not logged in", "doesnt exist",
        "corrupt", "not connected", "unknown server error"
    ]:
        if self._email is None:
            return "not logged in"

        if self._task.is_pending():
            if not self._ensure_server_connection():
                return "not connected"
            self._task_kind = "delete_item"
            self._task.start(self._do_delete_item, id)
            return "wait"

        result = self._task.get()
        if result is _TASK_RUNNING:
            return "wait"

        self._task.reset()
        return result

    def _do_delete_item(self, id: Uuid):
        try:
            items = self._items()
            if items is None or str(id) not in items:
                return "doesnt exist"

            # remove from our local tracking
            del items[str(id)]
            self._push_private_info()
            # Note: the server has no DeleteItemRequest, so we just remove it locally.
            # The item remains on the server but we lose our auth_key for it.
            return "done"
        except Exception:
            self._conn = None
            return "not connected"

    # ------------------------------------------------------------------
    # leave_and_release_item
    # ------------------------------------------------------------------

    def leave_and_release_item(self, id: Uuid) -> Literal[
        "wait", "done", "not logged in", "doesnt exist",
        "corrupt", "not connected", "unknown server error"
    ]:
        if self._email is None:
            return "not logged in"

        if self._task.is_pending():
            if not self._ensure_server_connection():
                return "not connected"
            self._task_kind = "leave_item"
            self._task.start(self._do_leave_item, id)
            return "wait"

        result = self._task.get()
        if result is _TASK_RUNNING:
            return "wait"

        self._task.reset()
        return result

    def _do_leave_item(self, id: Uuid):
        try:
            items = self._items()
            if items is None or str(id) not in items:
                return "doesnt exist"

            entry = items[str(id)]
            auth_key = entry["auth_key"]

            # fetch item contents
            self._conn.send(ItemRequest(id=str(id), auth_key=auth_key))
            r = ItemResponse(**self._recv_from_server())
            if r.is_success:
                try:
                    encrypted = bytes.fromhex(r.contents)
                    plaintext = self._aes_decrypt(encrypted, auth_key)
                    # release the key permanently (far future expiry)
                    self._conn.send(ReleaseItemRequest(
                        id=str(id),
                        auth_key=auth_key,
                        info=plaintext.hex(),
                        expires=datetime(9999, 12, 31).isoformat(),
                    ))
                    self._recv_from_server()
                except Exception:
                    pass

            del items[str(id)]
            self._push_private_info()
            return "done"
        except Exception:
            self._conn = None
            return "not connected"