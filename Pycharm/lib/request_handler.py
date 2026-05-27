from uuid import uuid4
from datetime import datetime

from lib.socket_wrapper import ServerConnection
from lib.database import Database, User, Item, ReleaseKey
from lib.request_response import *
from lib.email import Email, InvalidEmailError
from lib.encryption import encrypt
from lib.hashing import hash_string
from lib.encode_default import str_to_bytes, bytes_to_str


class Client:
    conn: ServerConnection
    logged_into_email: Email | None
    is_handling: bool

    def __init__(self, conn: ServerConnection):
        self.conn = conn
        self.logged_into_email = None
        self.is_handling = False


def handle_next_request(db: Database, client: Client):
    try:
        request = client.conn.recv()
        if request is None:
            return

        if not isinstance(request, dict):
            return

        req_type = request.get("type")
        if req_type is None:
            return

        try:
            if req_type == "SignupRequest":
                handle_signup_request(db, client, SignupRequest(**request))

            elif req_type == "LoginRequest":
                handle_login_request(db, client, LoginRequest(**request))

            elif req_type == "FetchRequest":
                handle_fetch_request(db, client, FetchRequest(**request))

            elif req_type == "PushRequest":
                handle_push_request(db, client, PushRequest(**request))

            elif req_type == "SendRequest":
                handle_send_request(db, client, SendRequest(**request))

            elif req_type == "ItemRequest":
                handle_item_request(db, client, ItemRequest(**request))

            elif req_type == "CreateItemRequest":
                handle_create_item_request(db, client, CreateItemRequest(**request))

            elif req_type == "EncryptItemRequest":
                handle_encrypt_item_request(db, client, EncryptItemRequest(**request))

            elif req_type == "ReleaseItemRequest":
                handle_release_item_request(db, client, ReleaseItemRequest(**request))
        except Exception as handler_err:
            print(f"Error handling {req_type}: {handler_err}")
            if req_type == "SignupRequest":
                client.conn.send(SignupResponse(is_success=False, email_is_taken=False))
            elif req_type == "LoginRequest":
                client.conn.send(LoginResponse(is_success=False, incorrect_password=False, user_doesnt_exist=False))
            elif req_type == "FetchRequest":
                client.conn.send(FetchResponse(is_success=False, not_logged_in=False, messages=[], private_info="", user_descriptions=[], user_emails=[], user_public_keys=[]))
            elif req_type == "PushRequest":
                client.conn.send(PushResponse(is_success=False, not_logged_in=False))
            elif req_type == "SendRequest":
                client.conn.send(SendResponse(is_success=False, invalid_email=False, user_doesnt_exist=False, not_logged_in=False))
            elif req_type == "ItemRequest":
                client.conn.send(ItemResponse(is_success=False, wrong_key=False, contents="", release_key_contents=[]))
            elif req_type == "CreateItemRequest":
                client.conn.send(CreateItemResponse(is_success=False, id=""))
            elif req_type == "EncryptItemRequest":
                client.conn.send(EncryptItemResponse(is_success=False, wrong_key=False))
            elif req_type == "ReleaseItemRequest":
                client.conn.send(ReleaseItemResponse(is_success=False, wrong_key=False))

    except Exception as e:
        # Prevent silent thread death → avoids "stalls"
        print("SERVER HANDLER CRASH:", e)
    finally:
        client.is_handling = False


def handle_signup_request(db: Database, client: Client, request: SignupRequest):
    print("signup fn")
    try:
        email = Email(request.email)
    except InvalidEmailError:
        client.conn.send(SignupResponse(is_success=False, email_is_taken=False))
        return

    if db.has_user(email=email):
        client.conn.send(SignupResponse(is_success=False, email_is_taken=True))
        return

    db.insert_user(
        email,
        User(
            auth_key=hash_string(request.auth_key),
            private_info=request.private_info,
            public_key=request.public_key,
            description=request.description,
            messages=[]
        ),
        should_already_exist=False
    )

    client.logged_into_email = email
    client.conn.send(SignupResponse(is_success=True, email_is_taken=False))


def handle_login_request(db: Database, client: Client, request: LoginRequest):
    try:
        email = Email(request.email)
    except InvalidEmailError:
        client.conn.send(LoginResponse(False, False, False))
        return

    if not db.has_user(email=email):
        client.conn.send(LoginResponse(False, False, True))
        return

    db_auth_key = db.get_user_auth_key(email)
    if hash_string(request.auth_key) != db_auth_key:
        client.conn.send(LoginResponse(False, True, False))
        return

    client.logged_into_email = email
    client.conn.send(LoginResponse(True, False, False))


# ============================================================
# FETCH
# ============================================================

def handle_fetch_request(db: Database, client: Client, _request: FetchRequest):
    if client.logged_into_email is None:
        client.conn.send(FetchResponse(
            is_success=False,
            not_logged_in=True,
            messages=[],
            private_info="",
            user_descriptions=[],
            user_emails=[],
            user_public_keys=[],
        ))
        return

    db_user = db.get_user(client.logged_into_email)
    if db_user is None:
        client.conn.send(FetchResponse(
            is_success=False,
            not_logged_in=False,
            messages=[],
            private_info="",
            user_descriptions=[],
            user_emails=[],
            user_public_keys=[],
        ))
        return

    users = db.get_user_emails_descs_pub_keys()

    client.conn.send(FetchResponse(
        is_success=True,
        not_logged_in=False,
        messages=db_user.messages,
        private_info=db_user.private_info,
        user_emails=[u[0].string for u in users],
        user_descriptions=[u[1] for u in users],
        user_public_keys=[u[2] for u in users],
    ))


# ============================================================
# PUSH
# ============================================================

def handle_push_request(db: Database, client: Client, request: PushRequest):
    if client.logged_into_email is None:
        client.conn.send(PushResponse(False, True))
        return

    db_user = db.get_user(client.logged_into_email)
    if db_user is None:
        client.conn.send(PushResponse(False, False))
        return

    db_user.private_info = request.private_info
    db_user.messages = request.messages

    db.insert_user(client.logged_into_email, db_user, should_already_exist=True)

    client.conn.send(PushResponse(True, False))


# ============================================================
# SEND MESSAGE
# ============================================================

def handle_send_request(db: Database, client: Client, request: SendRequest):
    if client.logged_into_email is None:
        client.conn.send(SendResponse(False, False, False, True))
        return

    try:
        target_email = Email(request.target_email)
    except InvalidEmailError:
        client.conn.send(SendResponse(False, False, True, False))
        return

    db_user = db.get_user(target_email)
    if db_user is None:
        client.conn.send(SendResponse(False, True, False, False))
        return

    db_user.messages.append(request.content)
    db.insert_user(target_email, db_user, should_already_exist=True)

    client.conn.send(SendResponse(True, False, False, False))


# ============================================================
# ITEM SYSTEM
# ============================================================

def handle_item_request(db: Database, client: Client, request: ItemRequest):
    db_auth_key = db.get_item_auth_key(request.id)

    if db_auth_key is None:
        client.conn.send(ItemResponse(False, False, "", []))
        return

    if hash_string(request.auth_key) != db_auth_key:
        client.conn.send(ItemResponse(False, True, "", []))
        return

    db_item = db.get_item(request.id)
    if db_item is None:
        client.conn.send(ItemResponse(False, False, "", []))
        return

    client.conn.send(ItemResponse(
        is_success=True,
        wrong_key=False,
        contents=db_item.contents,
        release_key_contents=[r.info for r in db_item.release_keys]
    ))


def handle_create_item_request(db: Database, client: Client, request: CreateItemRequest):
    item_id = str(uuid4())

    db.insert_item(
        item_id,
        Item(
            auth_key=hash_string(request.auth_key),
            contents=request.contents,
            release_keys=[]
        ),
        should_already_exist=False
    )

    client.conn.send(CreateItemResponse(True, item_id))


def handle_encrypt_item_request(db: Database, client: Client, request: EncryptItemRequest):
    db_auth_key = db.get_item_auth_key(request.id)

    if db_auth_key is None:
        client.conn.send(EncryptItemResponse(False, False))
        return

    if hash_string(request.auth_key) != db_auth_key:
        client.conn.send(EncryptItemResponse(False, True))
        return

    db_item = db.get_item(request.id)
    if db_item is None:
        client.conn.send(EncryptItemResponse(False, False))
        return

    encrypted = encrypt(request.public_key, str_to_bytes(db_item.contents))

    db_item.contents = request.prefix + bytes_to_str(encrypted)
    db.insert_item(request.id, db_item, should_already_exist=True)

    client.conn.send(EncryptItemResponse(True, False))


def handle_release_item_request(db: Database, client: Client, request: ReleaseItemRequest):
    db_auth_key = db.get_item_auth_key(request.id)

    if db_auth_key is None:
        client.conn.send(ReleaseItemResponse(False, False))
        return

    if hash_string(request.auth_key) != db_auth_key:
        client.conn.send(ReleaseItemResponse(False, True))
        return

    db_item = db.get_item(request.id)
    if db_item is None:
        client.conn.send(ReleaseItemResponse(False, False))
        return

    expires = datetime.fromisoformat(request.expires)

    db_item.release_keys.append(
        ReleaseKey(info=request.info, expires=expires)
    )

    db.insert_item(request.id, db_item, should_already_exist=True)

    client.conn.send(ReleaseItemResponse(True, False))
