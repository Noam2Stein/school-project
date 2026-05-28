from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from uuid import UUID as UUID
from datetime import datetime
from typing import Literal

from lib.socket_wrapper import try_connect_to_server, ClientConnection
from lib.request_response import (
    Request,

    SignupRequest,
    LoginRequest,
    FetchRequest,
    PushRequest,
    SendRequest,
    ItemRequest,
    CreateItemRequest,
    EncryptItemRequest,
    ReleaseItemRequest,

    PublicKey,
)
from lib.encryption import (
    keypair,
    encrypt,
    decrypt,
    PrivateKey,
)
from lib.hashing import hash_string
from lib.task import Task
from lib.email import Email, InvalidEmailError
from lib.encode_default import bytes_to_str, str_to_bytes


@dataclass
class _PrivateInformation:
    item_ids: list[str]
    item_auth_keys: list[str]
    item_names: list[str]
    item_encryption_methods: list[str]
    item_sizes: list[int]

    def __init__(self):
        self.item_ids = []
        self.item_auth_keys = []
        self.item_names = []
        self.item_encryption_methods = []
        self.item_sizes = []


class _ItemMetadata:
    id: str
    name: str
    auth_key: str
    encryption_method: str
    is_released: bool
    released_until: datetime | None
    size: int

    def __init__(
        self,
        id: str,
        name: str,
        auth_key: str,
        encryption_method: str,
        size: int = 0,
    ):
        self.id = id
        self.name = name
        self.auth_key = auth_key
        self.encryption_method = encryption_method
        self.is_released = False
        self.released_until = None
        self.size = size


class _InvitationMetadata:
    id: str
    name: str
    auth_key: str
    encryption_method: str
    size: int

    def __init__(
        self,
        id: str,
        name: str,
        auth_key: str,
        encryption_method: str,
        size: int = 0,
    ):
        self.id = id
        self.name = name
        self.auth_key = auth_key
        self.encryption_method = encryption_method
        self.size = size


class _AccountInfo:
    email: Email
    auth_key: str

    private_key: PrivateKey
    public_key: PublicKey

    private_info: _PrivateInformation

    item_metadata: list[_ItemMetadata]
    invitation_metadata: list[_InvitationMetadata]

    def __init__(
        self,
        email: Email,
        auth_key: str,
        private_key: PrivateKey,
        public_key: PublicKey,
    ):
        self.email = email
        self.auth_key = auth_key

        self.private_key = private_key
        self.public_key = public_key

        self.private_info = _PrivateInformation()

        self.item_metadata = []
        self.invitation_metadata = []


class GlobalInfo:
    global_user_emails: list[str] | None
    global_user_pub_keys: list[PublicKey] | None
    global_user_descriptions: list[str] | None


def _serialize_private_info(
    private_info: _PrivateInformation,
    public_key: PublicKey,
) -> str:
    serialized = json.dumps(asdict(private_info)).encode()

    encrypted = encrypt(
        public_key,
        serialized,
    )

    return bytes_to_str(encrypted)


def _deserialize_private_info(
    serialized: str,
    private_key: PrivateKey,
) -> _PrivateInformation | Literal["corrupt"]:
    try:
        decrypted = decrypt(
            private_key,
            str_to_bytes(serialized),
        )

        loaded = json.loads(decrypted.decode())

        result = _PrivateInformation()

        result.item_ids = loaded.get("item_ids", [])
        result.item_auth_keys = loaded.get("item_auth_keys", [])
        result.item_names = loaded.get("item_names", [])
        result.item_encryption_methods = loaded.get("item_encryption_methods", [])
        result.item_sizes = loaded.get("item_sizes", [])

        return result
    except Exception:
        return "corrupt"


class ClientBackend:
    _task: Task | None
    _conn: ClientConnection | None
    _global_info: GlobalInfo | None
    _account: _AccountInfo | None

    def __init__(self):
        self._task = None
        self._conn = None
        self._global_info = None
        self._account = None

    def _connect(self) -> bool:
        if self._conn is not None:
            return True

        self._conn = try_connect_to_server()

        return self._conn is not None

    def _request(
        self,
        request: Request,
    ) -> dict | Literal["not connected"]:
        if not self._connect():
            return "not connected"

        self._conn.send(request)

        while True:
            response = self._conn.recv()

            if response is not None:
                return response

    def fetch_from_server(self) -> Literal[
        "wait",
        "not connected",
        "done",
        "unknown server error",
    ]:
        if self._account is None:
            return "unknown server error"

        if self._task is not None and self._task.name == "fetch":
            if self._task.is_pending():
                return "wait"

            result = self._task.get()
            self._task = None

            return result

        def run() -> Literal[
            "done",
            "not connected",
            "unknown server error",
        ]:
            response = self._request(FetchRequest())

            if response["error"] is not None:
                return response["error"]

            private_info = _deserialize_private_info(
                response["private_info"],
                self._account.private_key,
            )

            if private_info == "corrupt":
                return "unknown server error"

            self._account.private_info = private_info

            # Rebuild item_metadata from the decrypted private_info
            self._account.item_metadata = []
            for i in range(len(private_info.item_ids)):
                item_id = private_info.item_ids[i]
                auth_key = private_info.item_auth_keys[i]
                
                # Fetch optional metadata with safe fallbacks
                name = private_info.item_names[i] if i < len(private_info.item_names) else "unknown"
                method = private_info.item_encryption_methods[i] if i < len(private_info.item_encryption_methods) else "plain"
                size = private_info.item_sizes[i] if i < len(private_info.item_sizes) else 0

                self._account.item_metadata.append(_ItemMetadata(
                    id=item_id,
                    name=name,
                    auth_key=auth_key,
                    encryption_method=method,
                    size=size,
                ))

            global_info = GlobalInfo()
            global_info.global_user_emails = response["user_emails"]
            global_info.global_user_pub_keys = response["user_public_keys"]
            global_info.global_user_descriptions = response["user_descriptions"]

            self._global_info = global_info

            self._account.invitation_metadata = []

            for message in response["messages"]:
                try:
                    decrypted = decrypt(
                        self._account.private_key,
                        str_to_bytes(message),
                    )

                    loaded = json.loads(decrypted.decode())

                    invitation = _InvitationMetadata(
                        loaded["item_id"],
                        loaded["item_name"],
                        loaded["item_auth_key"],
                        loaded["item_encryption_method"],
                        loaded.get("item_size", 0),
                    )

                    self._account.invitation_metadata.append(invitation)
                except Exception:
                    continue

            self._request(PushRequest(
                private_info=response["private_info"],
                messages=[],
            ))

            return "done"

        self._task = Task("fetch", run)

        return "wait"

    def global_user_emails(self) -> list[str] | Literal["havent fetched"]:
        if self._global_info is None:
            return "havent fetched"

        if self._global_info.global_user_emails is None:
            return "havent fetched"

        return self._global_info.global_user_emails

    def global_user_description(
        self,
        email: str,
    ) -> str | Literal["havent fetched", "doesnt exist"]:
        if self._global_info is None:
            return "havent fetched"

        if self._global_info.global_user_emails is None:
            return "havent fetched"

        if self._global_info.global_user_descriptions is None:
            return "havent fetched"

        if email not in self._global_info.global_user_emails:
            return "doesnt exist"

        index = self._global_info.global_user_emails.index(email)

        return self._global_info.global_user_descriptions[index]

    def login(self, email: str, password: str) -> Literal[
        "wait",
        "done",
        "not connected",
        "wrong password",
        "unknown server error",
    ]:
        if self._task is not None and self._task.name == "login":
            if self._task.is_pending():
                return "wait"

            result = self._task.get()
            self._task = None

            return result

        def run() -> Literal[
            "done",
            "not connected",
            "wrong password",
            "unknown server error",
        ]:
            auth_key = hash_string(password)

            response = self._request(LoginRequest(
                email=email,
                auth_key=auth_key,
            ))

            if response["error"] is not None:
                return response["error"]

            private_key, public_key = keypair(password)

            self._account = _AccountInfo(
                Email(email),
                auth_key,
                private_key,
                public_key,
            )

            # Immediately fetch and fully load account state
            fetch_response = self._request(FetchRequest())

            if fetch_response["error"] is not None:
                return fetch_response["error"]

            private_info = _deserialize_private_info(
                fetch_response["private_info"],
                self._account.private_key,
            )

            if private_info == "corrupt":
                return "unknown server error"

            self._account.private_info = private_info

            # Rebuild item metadata
            self._account.item_metadata = []

            for i in range(len(private_info.item_ids)):
                item_id = private_info.item_ids[i]
                auth_key = private_info.item_auth_keys[i]

                name = (
                    private_info.item_names[i]
                    if i < len(private_info.item_names)
                    else "unknown"
                )

                method = (
                    private_info.item_encryption_methods[i]
                    if i < len(private_info.item_encryption_methods)
                    else "plain"
                )

                size = (
                    private_info.item_sizes[i]
                    if i < len(private_info.item_sizes)
                    else 0
                )

                self._account.item_metadata.append(_ItemMetadata(
                    id=item_id,
                    name=name,
                    auth_key=auth_key,
                    encryption_method=method,
                    size=size,
                ))

            # Load global info
            global_info = GlobalInfo()
            global_info.global_user_emails = fetch_response["user_emails"]
            global_info.global_user_pub_keys = fetch_response["user_public_keys"]
            global_info.global_user_descriptions = fetch_response["user_descriptions"]

            self._global_info = global_info

            # Load invitations
            self._account.invitation_metadata = []

            for message in fetch_response["messages"]:
                try:
                    decrypted = decrypt(
                        self._account.private_key,
                        str_to_bytes(message),
                    )

                    loaded = json.loads(decrypted.decode())

                    invitation = _InvitationMetadata(
                        loaded["item_id"],
                        loaded["item_name"],
                        loaded["item_auth_key"],
                        loaded["item_encryption_method"],
                        loaded.get("item_size", 0),
                    )

                    self._account.invitation_metadata.append(invitation)

                except Exception:
                    continue

            return "done"

        self._task = Task("login", run)

        return "wait"

    def signup(self, email: str, password: str, description: str) -> Literal[
        "wait",
        "done",
        "already exists",
        "invalid password (must be atleast 4 characters)",
        "invalid email syntax",
        "not connected",
        "unknown server error",
    ]:
        if len(password) < 4:
            return "invalid password (must be atleast 4 characters)"

        try:
            validated_email = Email(email)
        except InvalidEmailError:
            return "invalid email syntax"

        if self._task is not None and self._task.name == "signup":
            if self._task.is_pending():
                return "wait"

            result = self._task.get()
            self._task = None

            return result

        def run() -> Literal[
            "done",
            "already exists",
            "not connected",
            "unknown server error",
        ]:
            auth_key = hash_string(password)

            private_key, public_key = keypair(password)

            account = _AccountInfo(
                validated_email,
                auth_key,
                private_key,
                public_key,
            )

            serialized_private_info = _serialize_private_info(
                account.private_info,
                public_key,
            )

            response = self._request(SignupRequest(
                email=email,
                auth_key=auth_key,
                private_info=serialized_private_info,
                public_key=public_key,
            ))

            if response["error"] is not None:
                return response["error"]

            self._account = account

            return "done"

        self._task = Task("signup", run)

        return "wait"

    def logged_into_email(self) -> str | Literal["not logged in"]:
        if self._account is None:
            return "not logged in"

        return self._account.email.string

    def my_item_ids(
        self,
    ) -> list[UUID] | Literal["not logged in", "havent fetched"]:
        if self._account is None:
            return "not logged in"

        return [UUID(item_id) for item_id in self._account.private_info.item_ids]

    def my_item_invitation_ids(
        self,
    ) -> list[UUID] | Literal["not logged in", "havent fetched"]:
        if self._account is None:
            return "not logged in"

        return [
            UUID(invitation.id)
            for invitation in self._account.invitation_metadata
        ]

    def item_name(
        self,
        id: UUID,
    ) -> str | Literal["not logged in", "havent fetched", "doesnt exist"]:
        if self._account is None:
            return "not logged in"

        sid = str(id)

        for item in self._account.item_metadata:
            if item.id == sid:
                return item.name

        for invitation in self._account.invitation_metadata:
            if invitation.id == sid:
                return invitation.name

        return "doesnt exist"

    def item_encryption_method(
        self,
        id: UUID,
    ) -> str | Literal["not logged in", "havent fetched", "doesnt exist"]:
        if self._account is None:
            return "not logged in"

        sid = str(id)

        for item in self._account.item_metadata:
            if item.id == sid:
                return item.encryption_method

        for invitation in self._account.invitation_metadata:
            if invitation.id == sid:
                return invitation.encryption_method

        return "doesnt exist"

    def item_size(
        self,
        id: UUID,
    ) -> int | Literal["not logged in", "havent fetched", "doesnt exist"]:
        if self._account is None:
            return "not logged in"

        sid = str(id)

        for item in self._account.item_metadata:
            if item.id == sid:
                return getattr(item, "size", 0)

        for invitation in self._account.invitation_metadata:
            if invitation.id == sid:
                return getattr(invitation, "size", 0)

        return "doesnt exist"

    def item_is_locked(
        self,
        id: UUID,
    ) -> bool | Literal[
        "not logged in",
        "havent fetched",
        "doesnt exist",
        "corrupt",
    ]:
        if self._account is None:
            return "not logged in"

        sid = str(id)

        auth_key: str | None = None
        for item in self._account.item_metadata:
            if item.id == sid:
                auth_key = item.auth_key
                break

        if auth_key is None:
            for invitation in self._account.invitation_metadata:
                if invitation.id == sid:
                    auth_key = invitation.auth_key
                    break

        if auth_key is None:
            return "doesnt exist"

        # Synchronously query the server for the current locks and release keys
        response = self._request(ItemRequest(
            id=sid,
            auth_key=auth_key,
        ))

        if response == "not connected" or response["type"] != "ItemResponse":
            return "corrupt"

        if response.get("error") is not None:
            return "corrupt"

        locks_str = response.get("locks", "")
        if not locks_str or locks_str == "none":
            return False

        release_key_contents = response.get("release_key_contents", [])

        # Pool of available private keys
        private_keys = [self._account.private_key]
        for rk_info in release_key_contents:
            try:
                private_keys.append(PrivateKey(rk_info))
            except Exception:
                continue

        current_locks = locks_str
        while True:
            if ":" not in current_locks:
                if current_locks == "none" or not current_locks:
                    return False
                break

            prefix, b64_payload = current_locks.rsplit(":", 1)
            try:
                encrypted_bytes = str_to_bytes(b64_payload)
            except Exception:
                break

            decrypted = None
            for pk in private_keys:
                try:
                    decrypted = decrypt(pk, encrypted_bytes)
                    break
                except Exception:
                    continue

            if decrypted is None:
                # We couldn't decrypt this layer, so it is locked!
                return True

            current_locks = decrypted.decode("utf-8", errors="ignore")

        return True

    def read_item(
        self,
        id: UUID,
    ) -> bytes | Literal[
        "wait",
        "not connected",
        "not logged in",
        "havent fetched",
        "doesnt exist",
        "locked",
        "corrupt",
        "unknown server error",
    ]:
        if self._account is None:
            return "not logged in"

        if self._task is not None and self._task.name == "read_item":
            if self._task.is_pending():
                return "wait"

            result = self._task.get()
            self._task = None

            return result

        def run() -> bytes | Literal[
            "not connected",
            "doesnt exist",
            "locked",
            "corrupt",
            "unknown server error",
        ]:
            sid = str(id)

            auth_key: str | None = None

            for item in self._account.item_metadata:
                if item.id == sid:
                    auth_key = item.auth_key
                    break

            if auth_key is None:
                for invitation in self._account.invitation_metadata:
                    if invitation.id == sid:
                        auth_key = invitation.auth_key
                        break

            if auth_key is None:
                return "doesnt exist"

            response = self._request(ItemRequest(
                id=sid,
                auth_key=auth_key,
            ))

            if response["error"] is not None:
                return response["error"]

            contents = str_to_bytes(response["contents"])

            private_keys = [self._account.private_key]
            for rk_info in response["release_key_contents"]:
                try:
                    private_keys.append(PrivateKey(rk_info))
                except Exception:
                    continue

            # Iteratively decrypt the layer by layer
            while True:
                content_str = contents.decode("utf-8", errors="ignore")
                if ":" not in content_str:
                    break

                prefix, b64_payload = content_str.rsplit(":", 1)
                try:
                    encrypted_bytes = str_to_bytes(b64_payload)
                except Exception:
                    break

                decrypted = None
                for pk in private_keys:
                    try:
                        decrypted = decrypt(pk, encrypted_bytes)
                        break
                    except Exception:
                        continue

                if decrypted is None:
                    return "locked"

                contents = decrypted

            return contents

        self._task = Task("read_item", run)

        return "wait"

    def release_item(
        self,
        id: UUID,
        until: datetime,
    ) -> Literal[
        "wait",
        "done",
        "not logged in",
        "havent fetched",
        "doesnt exist",
        "corrupt",
        "havent joined",
        "unknown server error",
    ]:
        if self._account is None:
            return "not logged in"

        if self._task is not None and self._task.name == "release_item":
            if self._task.is_pending():
                return "wait"

            result = self._task.get()
            self._task = None

            return result

        def run() -> Literal[
            "done",
            "doesnt exist",
            "corrupt",
            "havent joined",
            "unknown server error",
        ]:
            sid = str(id)

            item: _ItemMetadata | None = None

            for current_item in self._account.item_metadata:
                if current_item.id == sid:
                    item = current_item
                    break

            if item is None:
                return "havent joined"

            response = self._request(ReleaseItemRequest(
                id=sid,
                auth_key=item.auth_key,
                info=str(self._account.private_key),
                expires=until.isoformat(),
            ))

            if response["error"] is not None:
                return response["error"]

            item.is_released = True
            item.released_until = until

            return "done"

        self._task = Task("release_item", run)

        return "wait"

    def join_item(
        self,
        id: UUID,
    ) -> Literal[
        "wait",
        "done",
        "not logged in",
        "havent fetched",
        "doesnt exist",
        "corrupt",
        "unknown server error",
    ]:
        if self._account is None:
            return "not logged in"

        sid = str(id)

        invitation: _InvitationMetadata | None = None

        for current_invitation in self._account.invitation_metadata:
            if current_invitation.id == sid:
                invitation = current_invitation
                break

        if invitation is None:
            return "doesnt exist"

        self._account.private_info.item_ids.append(invitation.id)
        self._account.private_info.item_auth_keys.append(invitation.auth_key)
        self._account.private_info.item_names.append(invitation.name)
        self._account.private_info.item_encryption_methods.append(invitation.encryption_method)
        self._account.private_info.item_sizes.append(invitation.size)

        self._account.item_metadata.append(_ItemMetadata(
            invitation.id,
            invitation.name,
            invitation.auth_key,
            invitation.encryption_method,
            invitation.size,
        ))

        self._account.invitation_metadata.remove(invitation)

        response = self._request(PushRequest(
            private_info=_serialize_private_info(
                self._account.private_info,
                self._account.public_key,
            ),
            messages=[],
        ))

        if response["error"] is not None:
            return response["error"]

        return "done"

    def reject_item(
        self,
        id: UUID,
    ) -> Literal[
        "wait",
        "done",
        "not logged in",
        "havent fetched",
        "doesnt exist",
        "corrupt",
        "unknown server error",
    ]:
        if self._account is None:
            return "not logged in"

        sid = str(id)

        invitation: _InvitationMetadata | None = None

        for current_invitation in self._account.invitation_metadata:
            if current_invitation.id == sid:
                invitation = current_invitation
                break

        if invitation is None:
            return "doesnt exist"

        self._account.invitation_metadata.remove(invitation)

        return "done"

    def has_released_item(
        self,
        id: UUID,
    ) -> bool | Literal[
        "not logged in",
        "havent fetched",
        "doesnt exist",
        "corrupt",
    ]:
        if self._account is None:
            return "not logged in"

        sid = str(id)

        for item in self._account.item_metadata:
            if item.id == sid:
                return item.is_released

        return "doesnt exist"

    def released_item_timelimit(
        self,
        id: UUID,
    ) -> datetime | Literal[
        "not logged in",
        "havent fetched",
        "doesnt exist",
        "corrupt",
        "havent released",
    ]:
        if self._account is None:
            return "not logged in"

        sid = str(id)

        for item in self._account.item_metadata:
            if item.id == sid:
                if not item.is_released:
                    return "havent released"

                if item.released_until is None:
                    return "havent released"

                return item.released_until

        return "doesnt exist"

    def create_item(
        self,
        name: str,
        data: bytes,
    ) -> Literal[
        "wait",
        "done",
        "not logged in",
        "corrupt",
        "not connected",
        "unknown server error",
    ]:
        if self._account is None:
            return "not logged in"

        if self._task is not None and self._task.name == "create_item":
            if self._task.is_pending():
                return "wait"

            result = self._task.get()
            self._task = None

            return result

        def run() -> Literal[
            "done",
            "not connected",
            "unknown server error",
        ]:
            auth_key = hash_string(name + str(datetime.now().timestamp()))

            locks_val = self._account.email.string + ":" + bytes_to_str(encrypt(self._account.public_key, b"none"))

            response = self._request(CreateItemRequest(
                contents=bytes_to_str(data),
                auth_key=auth_key,
                locks=locks_val,
            ))

            if response["error"] is not None:
                return response["error"]

            item_id = response["id"]

            self._account.private_info.item_ids.append(item_id)
            self._account.private_info.item_auth_keys.append(auth_key)
            self._account.private_info.item_names.append(name)
            self._account.private_info.item_encryption_methods.append("plain")
            self._account.private_info.item_sizes.append(len(data))

            self._account.item_metadata.append(_ItemMetadata(
                item_id,
                name,
                auth_key,
                "plain",
                len(data),
            ))

            push_response = self._request(PushRequest(
                private_info=_serialize_private_info(
                    self._account.private_info,
                    self._account.public_key,
                ),
                messages=[],
            ))

            if push_response["error"] is not None:
                return push_response["error"]

            return "done"

        self._task = Task("create_item", run)

        return "wait"

    def invite_user_to_item(
        self,
        user_email: str,
        item_id: UUID,
    ) -> Literal[
        "wait",
        "done",
        "not logged in",
        "corrupt",
        "not connected",
        "item doesnt exist",
        "user doesnt exist",
        "unknown server error",
    ]:
        if self._account is None:
            return "not logged in"

        if self._global_info is None:
            return "unknown server error"

        if self._global_info.global_user_emails is None:
            return "unknown server error"

        if self._global_info.global_user_pub_keys is None:
            return "unknown server error"

        sid = str(item_id)

        item: _ItemMetadata | None = None

        for current_item in self._account.item_metadata:
            if current_item.id == sid:
                item = current_item
                break

        if item is None:
            return "item doesnt exist"

        if user_email not in self._global_info.global_user_emails:
            return "user doesnt exist"

        index = self._global_info.global_user_emails.index(user_email)

        target_key = self._global_info.global_user_pub_keys[index]

        # Request the server to encrypt the item with the target user's public key
        prefix = user_email + ":"
        encrypt_response = self._request(EncryptItemRequest(
            id=sid,
            auth_key=item.auth_key,
            public_key=target_key,
            prefix=prefix,
        ))

        if encrypt_response["error"] is not None:
            return encrypt_response["error"]

        # Update metadata locally
        item.encryption_method = "encrypted"
        # Overhead: prefix length + original size + 64 bytes (ChaCha20Poly1305 encryption overhead)
        item.size = len(prefix) + item.size + 64

        try:
            priv_idx = self._account.private_info.item_ids.index(sid)
            self._account.private_info.item_encryption_methods[priv_idx] = "encrypted"
            self._account.private_info.item_sizes[priv_idx] = item.size
        except Exception:
            pass

        push_response = self._request(PushRequest(
            private_info=_serialize_private_info(
                self._account.private_info,
                self._account.public_key,
            ),
            messages=[],
        ))

        if push_response["error"] is not None:
            return push_response["error"]

        payload = json.dumps({
            "item_id": item.id,
            "item_name": item.name,
            "item_auth_key": item.auth_key,
            "item_encryption_method": item.encryption_method,
            "item_size": item.size,
        }).encode()

        encrypted_payload = encrypt(
            target_key,
            payload,
        )

        response = self._request(SendRequest(
            target_email=user_email,
            content=bytes_to_str(encrypted_payload),
        ))

        if response["error"] is not None:
            return response["error"]

        return "done"

    def delete_item(
        self,
        id: UUID,
    ) -> Literal[
        "wait",
        "done",
        "not logged in",
        "doesnt exist",
        "corrupt",
        "not connected",
        "unknown server error",
    ]:
        if self._account is None:
            return "not logged in"

        sid = str(id)

        index: int | None = None

        for i, item_id in enumerate(self._account.private_info.item_ids):
            if item_id == sid:
                index = i
                break

        if index is None:
            return "doesnt exist"

        del self._account.private_info.item_ids[index]
        del self._account.private_info.item_auth_keys[index]
        if index < len(self._account.private_info.item_names):
            del self._account.private_info.item_names[index]
        if index < len(self._account.private_info.item_encryption_methods):
            del self._account.private_info.item_encryption_methods[index]
        if index < len(self._account.private_info.item_sizes):
            del self._account.private_info.item_sizes[index]

        for item in self._account.item_metadata:
            if item.id == sid:
                self._account.item_metadata.remove(item)
                break

        response = self._request(PushRequest(
            private_info=_serialize_private_info(
                self._account.private_info,
                self._account.public_key,
            ),
            messages=[],
        ))

        if response["error"] is not None:
            return response["error"]

        return "done"

    def leave_and_release_item(
        self,
        id: UUID,
    ) -> Literal[
        "wait",
        "done",
        "not logged in",
        "doesnt exist",
        "corrupt",
        "not connected",
        "unknown server error",
    ]:
        release_result = self.release_item(
            id,
            datetime.max,
        )

        if release_result == "wait":
            return "wait"

        if release_result != "done":
            if release_result == "havent joined":
                return "doesnt exist"

            return release_result

        return self.delete_item(id)
