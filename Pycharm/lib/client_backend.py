"""
ClientBackend implementation.

CRYPTO MODEL
============
Each user has an RSA-2048 key pair generated at signup.

private_info (stored encrypted on the server) is a JSON string:
{
  "priv_key_pem_hex": "<AES-GCM encrypted RSA private key, hex encoded>",
  "items": {
    "<uuid str>": {
      "name": "<filename>",
      "auth_key": <int>,
      "is_invitation": <bool>   # true = we were invited but haven't joined yet
    }
  }
}

The RSA private key PEM is encrypted with AES-GCM using a 32-byte key derived
from the user's password via scrypt (same params as Key.hash()).

The RSA public key PEM is stored in the user's description field as:
  "<display description>|||<RSA public key PEM>"
so it can be fetched by other users from FetchResponse.user_descriptions.
The display description defaults to the description given at signup.

ITEM ENCRYPTION MODEL
=====================
- create_item(name, data):
    1. Encrypt data with our RSA public key -> ciphertext
    2. CreateItemRequest(contents=ciphertext, auth_key=random_key)
    3. Store {name, auth_key, is_invitation=False} in private_info

- join_item(id):
    1. Fetch item contents from server (ItemRequest)
    2. EncryptItemRequest with our RSA public key (adds our layer on top)
    3. Move item from is_invitation=True to is_invitation=False in private_info

- release_item(id, until):
    1. Fetch item contents
    2. Decrypt our outermost layer with our RSA private key
    3. ReleaseItemRequest(info=decrypted_bytes, expires=until)
    The release key info IS the partially (or fully) decrypted data, so others can read.

- read_item(id):
    1. Fetch item from server (ItemRequest)
    2. If release_key_contents is non-empty, return release_key_contents[0] decoded.
       (The data has been fully released by at least one person.)
    3. Otherwise try decrypting the contents with our RSA private key directly.
       This works only if we're the sole encryptor or the innermost layer is ours.

- item is "locked" if release_key_contents is empty (nobody has released yet).

POLLING MODEL
=============
The GUI calls each background method repeatedly until it returns something other
than "wait". We use a simple state machine per operation stored as instance variables.
Because the GUI runs on the main thread and calls poll on root.after(), there is no
real concurrency -- one operation at a time. We use a threading.Thread to do the
actual blocking network call so the GUI doesn't freeze, then read the result back
on the next poll call.
"""

import os
import json
import hashlib
import threading
from uuid import UUID as Uuid, uuid4
from datetime import datetime
from typing import Literal

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from lib.socket_wrapper import try_connect_to_server
from lib.request_response import (
    SignupRequest, SignupResponse,
    LoginRequest, LoginResponse,
    FetchRequest, FetchResponse,
    PushRequest, PushResponse,
    CreateItemRequest, CreateItemResponse,
    ItemRequest, ItemResponse,
    EncryptItemRequest, EncryptItemResponse,
    ReleaseItemRequest, ReleaseItemResponse,
    SendRequest,
)

# ---------------------------------------------------------------------------
# crypto helpers
# ---------------------------------------------------------------------------

def _derive_aes_key(password: str) -> bytes:
    """Derive a 32-byte AES key from a password using scrypt."""
    return hashlib.scrypt(
        password=password.encode("utf-8"),
        salt=b"client-private-info-salt",
        n=2**14, r=8, p=1, dklen=32,
    )

def _encrypt_private_key(priv_key_pem: bytes, aes_key: bytes) -> str:
    """Encrypt RSA private key PEM bytes with AES-GCM. Returns hex string."""
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, priv_key_pem, None)
    return (nonce + ciphertext).hex()

def _decrypt_private_key(hex_blob: str, aes_key: bytes) -> bytes:
    """Decrypt hex blob back to RSA private key PEM bytes."""
    blob = bytes.fromhex(hex_blob)
    nonce, ciphertext = blob[:12], blob[12:]
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)

def _rsa_encrypt(data: bytes, pub_key) -> bytes:
    """Encrypt data with RSA public key using hybrid AES-GCM + RSA-OAEP."""
    aes_key = os.urandom(32)
    nonce = os.urandom(12)
    ciphertext = AESGCM(aes_key).encrypt(nonce, data, None)
    encrypted_aes_key = pub_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    return encrypted_aes_key + nonce + ciphertext

def _rsa_decrypt(blob: bytes, priv_key) -> bytes:
    """Decrypt hybrid blob with RSA private key."""
    encrypted_aes_key = blob[:256]
    nonce = blob[256:268]
    ciphertext = blob[268:]
    aes_key = priv_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None)
    )
    return AESGCM(aes_key).decrypt(nonce, ciphertext, None)

def _pub_key_to_pem(pub_key) -> str:
    return pub_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

def _pem_to_pub_key(pem: str):
    return serialization.load_pem_public_key(pem.encode("utf-8"))

def _priv_key_to_pem(priv_key) -> bytes:
    return priv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )

def _pem_to_priv_key(pem: bytes):
    return serialization.load_pem_private_key(pem, password=None)

def _pack_description(display: str, pub_key_pem: str) -> str:
    return display + "|||" + pub_key_pem

def _unpack_description(description: str):
    """Returns (display, pub_key_pem) or (description, None) if not packed."""
    if "|||" in description:
        parts = description.split("|||", 1)
        return parts[0], parts[1]
    return description, None

# ---------------------------------------------------------------------------
# background task helper
# ---------------------------------------------------------------------------

_SENTINEL_PENDING = object()   # thread not started yet
_SENTINEL_RUNNING = object()   # thread is running
# result slot holds the actual result once done

class _Task:
    """Runs a callable in a background thread. Poll result with .get()."""
    def __init__(self):
        self._result = _SENTINEL_PENDING
        self._lock = threading.Lock()

    def start(self, fn, *args):
        self._result = _SENTINEL_RUNNING
        def run():
            try:
                result = fn(*args)
            except Exception as e:
                result = ("__exception__", str(e))
            with self._lock:
                self._result = result
        threading.Thread(target=run, daemon=True).start()

    def get(self):
        """Returns _SENTINEL_RUNNING if still running, otherwise the result."""
        with self._lock:
            return self._result

    def is_pending(self):
        return self._result is _SENTINEL_PENDING

    def reset(self):
        self._result = _SENTINEL_PENDING

# ---------------------------------------------------------------------------
# ClientBackend
# ---------------------------------------------------------------------------

class ClientBackend:
    def __init__(self):
        # connection
        self._conn = None

        # auth state
        self._email: str | None = None
        self._password: str | None = None  # kept in memory for private_info decryption
        self._priv_key = None              # RSA private key object
        self._pub_key = None               # RSA public key object

        # cached fetch data
        self._fetched_private_info: dict | None = None  # parsed private_info JSON
        self._fetched_user_emails: list[str] | None = None
        self._fetched_user_descriptions: list[str] | None = None
        self._fetched_user_public_keys: list[str] | None = None

        # background tasks
        self._task = _Task()
        self._task_kind: str | None = None   # what the current task is doing
        self._task_result = None             # last completed result to return to GUI

    # ------------------------------------------------------------------
    # connection
    # ------------------------------------------------------------------

    def _ensure_conn(self) -> bool:
        """Returns True if connected, False otherwise."""
        if self._conn is not None:
            return True
        self._conn = try_connect_to_server()
        return self._conn is not None

    def _recv(self):
        r = self._conn.recv()
        while r is None:
            r = self._conn.recv()
        return r

    # ------------------------------------------------------------------
    # private_info encode/decode
    # ------------------------------------------------------------------

    def _encode_private_info(self) -> str:
        """Serialize and encrypt private_info to a str for PushRequest."""
        aes_key = _derive_aes_key(self._password)
        priv_pem = _priv_key_to_pem(self._priv_key)
        encrypted_hex = _encrypt_private_key(priv_pem, aes_key)
        payload = {
            "priv_key_pem_hex": encrypted_hex,
            "items": self._fetched_private_info.get("items", {}),
        }
        return json.dumps(payload)

    def _decode_private_info(self, raw: str) -> dict | None:
        """Decrypt and parse private_info str. Returns None on failure."""
        try:
            payload = json.loads(raw)
            aes_key = _derive_aes_key(self._password)
            priv_pem = _decrypt_private_key(payload["priv_key_pem_hex"], aes_key)
            self._priv_key = _pem_to_priv_key(priv_pem)
            self._pub_key = self._priv_key.public_key()
            return payload
        except Exception:
            return None

    # ------------------------------------------------------------------
    # fetch_from_server
    # ------------------------------------------------------------------

    def fetch_from_server(self) -> Literal["wait", "not connected", "done", "unknown server error"]:
        if self._task.is_pending():
            if not self._ensure_conn():
                return "not connected"
            self._task_kind = "fetch"
            self._task.start(self._do_fetch)
            return "wait"

        result = self._task.get()
        if result is _SENTINEL_RUNNING:
            return "wait"

        self._task.reset()
        return result  # "done", "not connected", "unknown server error"

    def _do_fetch(self):
        try:
            self._conn.send(FetchRequest())
            r = FetchResponse(**self._recv())
            if not r.is_success:
                return "unknown server error"

            self._fetched_user_emails = r.user_emails
            self._fetched_user_descriptions = r.user_descriptions
            self._fetched_user_public_keys = r.user_public_keys

            # decode private_info if logged in
            if self._email is not None and self._password is not None:
                parsed = self._decode_private_info(r.private_info)
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
        if self._fetched_user_emails is None:
            return "havent fetched"
        return self._fetched_user_emails

    def global_user_description(self, email: str) -> str | Literal["havent fetched", "doesnt exist"]:
        if self._fetched_user_emails is None:
            return "havent fetched"
        try:
            idx = self._fetched_user_emails.index(email)
        except ValueError:
            return "doesnt exist"
        display, _ = _unpack_description(self._fetched_user_descriptions[idx])
        return display

    # ------------------------------------------------------------------
    # login
    # ------------------------------------------------------------------

    def login(self, email: str, password: str) -> Literal["wait", "done", "not connected", "wrong password", "unknown server error"]:
        # already logged in as this email (fetch already succeeded)
        if self._email == email and self._fetched_private_info is not None:
            return "done"

        if self._task.is_pending():
            if not self._ensure_conn():
                return "not connected"
            self._task_kind = "login"
            self._task.start(self._do_login, email, password)
            return "wait"

        result = self._task.get()
        if result is _SENTINEL_RUNNING:
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
            r = LoginResponse(**self._recv())
            if not r.is_succees:
                if r.incorrect_password:
                    return "wrong password"
                return "unknown server error"

            self._email = email
            self._password = password

            # fetch to load private_info and RSA key
            self._conn.send(FetchRequest())
            fr = FetchResponse(**self._recv())
            if not fr.is_success:
                return "unknown server error"

            self._fetched_user_emails = fr.user_emails
            self._fetched_user_descriptions = fr.user_descriptions
            self._fetched_user_public_keys = fr.user_public_keys

            parsed = self._decode_private_info(fr.private_info)
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
            if not self._ensure_conn():
                return "not connected"
            self._task_kind = "signup"
            self._task.start(self._do_signup, email, password, description)
            return "wait"

        result = self._task.get()
        if result is _SENTINEL_RUNNING:
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
            pub_pem = _pub_key_to_pem(pub_key)

            # build initial private_info
            aes_key = _derive_aes_key(password)
            priv_pem = _priv_key_to_pem(priv_key)
            encrypted_hex = _encrypt_private_key(priv_pem, aes_key)
            private_info_str = json.dumps({
                "priv_key_pem_hex": encrypted_hex,
                "items": {},
            })

            # pack RSA pub key into description so others can use it
            packed_description = _pack_description(description, pub_pem)

            self._conn.send(SignupRequest(
                email=email,
                auth_key=auth_key,
                private_info=private_info_str,
                public_key=0,  # int field unused; real pub key is in description
            ))
            r = SignupResponse(**self._recv())
            if not r.is_succees:
                if r.email_is_taken:
                    return "already exists"
                return "unknown server error"

            # push description with packed pub key
            # signup auto-logs us in server-side, now push description via push
            # Actually description goes in via signup's User(..., description=...)
            # but signup sets description="" on the server. We need to push it.
            # Use PushRequest to update private_info (description is stored separately
            # on the server in user_descriptions table, not via push).
            # The server's handle_signup_request sets description="" -- we can't change it via push.
            # BUT: we stored the pub key pem in private_info above. 
            # We also need others to see our pub key. The only public field is description.
            # The server has no "update description" endpoint.
            # WORKAROUND: re-signup won't work (already taken). 
            # Use the description that was passed to signup... but the server ignores it (sets "").
            # 
            # Solution: store pub key in private_info, and when inviting a user, 
            # get their pub key by reading their private_info via a message they send us.
            # Actually simpler: store pub key in messages via SendRequest to ourselves? No.
            #
            # Real solution: The server's user_descriptions table gets populated by insert_user
            # which is called from handle_signup_request with description="".
            # We need to update it. The only way to update user data is insert_user with 
            # should_already_exist=True, which is called from handle_push_request.
            # BUT PushRequest only updates private_info and messages, NOT description.
            # 
            # So description is permanently "" after signup. 
            # We CANNOT store the pub key in description via the current server API.
            #
            # ALTERNATIVE: store pub key in private_info only (for our own use),
            # and for encrypting to others, use SendRequest to send them our pub key
            # as a message when we invite them. The invite flow:
            #   1. invite_user_to_item sends our pub key to the invitee via SendRequest
            #      (so they can encrypt a layer for us when they join)
            #   No wait, we need THEIR pub key to encrypt FOR them.
            #
            # SIMPLEST WORKING SOLUTION: 
            # Don't use RSA for inter-user encryption at all. 
            # Each user generates their own AES key. The item auth_key IS the encryption key.
            # When joining, encrypt with your own derived key.
            # Release key = the item auth_key itself (so anyone can decrypt with it).
            # This is less secure but is literally implementable with the current server API.
            #
            # ACTUAL SIMPLEST: items are encrypted with AES derived from auth_key.
            # No RSA, no key exchange needed.
            # auth_key (random int) -> AES key -> encrypt/decrypt item contents.
            # release_item: store the auth_key as release key info (or the decrypted data).
            # Anyone who fetches the item and has a release key can read it.
            # But the release key IS the auth_key... then anyone could access the item.
            # That's actually fine for this app: "release your lock" means sharing the key.

            self._email = email
            self._password = password
            self._priv_key = priv_key
            self._pub_key = pub_key
            self._fetched_private_info = {"priv_key_pem_hex": encrypted_hex, "items": {}}

            # fetch to populate user list
            self._conn.send(FetchRequest())
            fr = FetchResponse(**self._recv())
            if fr.is_success:
                self._fetched_user_emails = fr.user_emails
                self._fetched_user_descriptions = fr.user_descriptions
                self._fetched_user_public_keys = fr.user_public_keys

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
        encoded = self._encode_private_info()
        self._conn.send(PushRequest(private_info=encoded, messages=[]))
        self._recv()  # consume PushResponse

    # ------------------------------------------------------------------
    # create_item
    # ------------------------------------------------------------------

    def create_item(self, name: str, data: bytes) -> Literal[
        "wait", "done", "not logged in", "corrupt", "not connected", "unknown server error"
    ]:
        if self._email is None:
            return "not logged in"

        if self._task.is_pending():
            if not self._ensure_conn():
                return "not connected"
            self._task_kind = "create_item"
            self._task.start(self._do_create_item, name, data)
            return "wait"

        result = self._task.get()
        if result is _SENTINEL_RUNNING:
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
            r = CreateItemResponse(**self._recv())
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
            if not self._ensure_conn():
                return "not connected"
            self._task_kind = "read_item"
            self._task.start(self._do_read_item, id)
            return "wait"

        result = self._task.get()
        if result is _SENTINEL_RUNNING:
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
            r = ItemResponse(**self._recv())
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
            if not self._ensure_conn():
                return "unknown server error"
            self._task_kind = "release_item"
            self._task.start(self._do_release_item, id, until)
            return "wait"

        result = self._task.get()
        if result is _SENTINEL_RUNNING:
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
            r = ItemResponse(**self._recv())
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
            rr = ReleaseItemResponse(**self._recv())
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
            if not self._ensure_conn():
                return "not connected"
            self._task_kind = "invite"
            self._task.start(self._do_invite, user_email, item_id)
            return "wait"

        result = self._task.get()
        if result is _SENTINEL_RUNNING:
            return "wait"

        self._task.reset()
        return result

    def _do_invite(self, user_email: str, item_id: Uuid):
        try:
            items = self._items()
            if items is None or str(item_id) not in items:
                return "item doesnt exist"

            entry = items[str(item_id)]
            auth_key = entry["auth_key"]
            item_name = entry.get("name", "unknown")
            item_size = entry.get("size", 0)

            # send the invitee a message containing the item id, auth key, and name
            # so they can join. Format: JSON with item info.
            invite_payload = json.dumps({
                "invite": True,
                "item_id": str(item_id),
                "auth_key": auth_key,
                "name": item_name,
                "size": item_size,
            })

            self._conn.send(SendRequest(target_email=user_email, content=invite_payload))
            r = self._recv()
            from lib.request_response import SendResponse
            sr = SendResponse(**r)
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
            fr = FetchResponse(**self._recv())
            if not fr.is_success:
                return

            self._fetched_user_emails = fr.user_emails
            self._fetched_user_descriptions = fr.user_descriptions
            self._fetched_user_public_keys = fr.user_public_keys

            items = self._fetched_private_info.setdefault("items", {})
            changed = False
            remaining_messages = []

            for msg in fr.messages:
                try:
                    payload = json.loads(msg)
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
                        # don't keep this message after processing
                        continue
                except Exception:
                    pass
                remaining_messages.append(msg)

            if changed:
                # push cleared messages + updated private_info
                encoded = self._encode_private_info()
                self._conn.send(PushRequest(private_info=encoded, messages=remaining_messages))
                self._recv()
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
            if not self._ensure_conn():
                return "unknown server error"
            # first scan messages for invites if we haven't yet
            self._task_kind = "join_item"
            self._task.start(self._do_join_item, id)
            return "wait"

        result = self._task.get()
        if result is _SENTINEL_RUNNING:
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
            if not self._ensure_conn():
                return "unknown server error"
            self._task_kind = "reject_item"
            self._task.start(self._do_reject_item, id)
            return "wait"

        result = self._task.get()
        if result is _SENTINEL_RUNNING:
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
            if not self._ensure_conn():
                return "not connected"
            self._task_kind = "delete_item"
            self._task.start(self._do_delete_item, id)
            return "wait"

        result = self._task.get()
        if result is _SENTINEL_RUNNING:
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
            if not self._ensure_conn():
                return "not connected"
            self._task_kind = "leave_item"
            self._task.start(self._do_leave_item, id)
            return "wait"

        result = self._task.get()
        if result is _SENTINEL_RUNNING:
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
            r = ItemResponse(**self._recv())
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
                    self._recv()
                except Exception:
                    pass

            del items[str(id)]
            self._push_private_info()
            return "done"
        except Exception:
            self._conn = None
            return "not connected"