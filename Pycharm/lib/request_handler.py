from uuid import UUID as Uuid, uuid4

from lib.socket_wrapper import ServerConnection
from lib.database import Database, User, Item, ReleaseKey
from lib.request_response import *
from lib.email import Email, InvalidEmailError
from lib.key import Key, InvalidKeyError
from lib.encryption import encrypt


class Client:
    conn: ServerConnection
    _logged_into_email: Email | None

    def __init__(self, conn: ServerConnection):
        self.conn = conn
        self._logged_into_email = None

def handle_next_request(db: Database, client: Client):
    request = client.conn.recv()
    while request is None:
        request = client.conn.recv()

    if request["type"] == "SignupRequest":
        handle_signup_request(db, client, SignupRequest(**request))
    if request["type"] == "LoginRequest":
        handle_login_request(db, client, LoginRequest(**request))
    if request["type"] == "FetchRequest":
        handle_fetch_request(db, client, FetchRequest(**request))
    if request["type"] == "PushRequest":
        handle_push_request(db, client, PushRequest(**request))
    if request["type"] == "SendRequest":
        handle_send_request(db, client, SendRequest(**request))
    if request["type"] == "ItemRequest":
        handle_item_request(db, client, ItemRequest(**request))
    if request["type"] == "CreateItemRequest":
        handle_create_item_request(db, client, CreateItemRequest(**request))
    if request["type"] == "EncryptItemRequest":
        handle_encrypt_item_request(db, client, EncryptItemRequest(**request))
    if request["type"] == "ReleaseItemRequest":
        handle_release_item_request(db, client, ReleaseItemRequest(**request))

def handle_signup_request(db: Database, client: Client, request: SignupRequest):
    try:
        email = Email(request.email)
        auth_key = Key(request.auth_key)
        pub_key = Key(request.public_key)
    except InvalidEmailError:
        client.conn.send(SignupResponse(is_succees=False, email_is_taken=False))
        return
    except InvalidKeyError:
        client.conn.send(SignupResponse(is_succees=False, email_is_taken=False))
        return

    if db.has_user(email=email):
        client.conn.send(SignupResponse(is_succees=False, email_is_taken=True))
        return

    db.insert_user(
        email,
        User(
            auth_key=auth_key,
            private_info=request.private_info.encode("utf-8"),
            public_key=pub_key,
            description="",
            messages=[]
        ),
        should_already_exist=False
    )
    client._logged_into_email = email
    client.conn.send(SignupResponse(is_succees=True, email_is_taken=False))

def handle_login_request(db: Database, client: Client, request: LoginRequest):
    try:
        email = Email(request.email)
        auth_key = Key(request.auth_key)
    except:
        client.conn.send(LoginResponse(is_succees=False, incorrect_password=False, user_doesnt_exist=False))
        return

    if not db.has_user(email=email):
        client.conn.send(LoginResponse(is_succees=False, incorrect_password=False, user_doesnt_exist=True))
        return

    db_auth_key = db.get_user_auth_key(email)
    if auth_key != db_auth_key:
        client.conn.send(LoginResponse(is_succees=False, incorrect_password=True, user_doesnt_exist=False))
        return

    # Its bad practice to make the authentication success branch the normal
    # branch and the failure branch with early returns, but its very funny and
    # this is not a serious project so fuck it.

    client._logged_into_email = email
    client.conn.send(LoginResponse(is_succees=True, incorrect_password=False, user_doesnt_exist=False))

def handle_fetch_request(db: Database, client: Client, request: FetchRequest):
    if client._logged_into_email is None:
        client.conn.send(FetchResponse(
            is_success=False,
            isnt_logged_in=True,
            messages=[],
            private_info="",
            user_descriptions=[],
            user_emails=[],
            user_public_keys=[],
        ))
        return

    try:
        db_user = db.get_user(client._logged_into_email)
    except:
        client.conn.send(FetchResponse(
            is_success=False,
            isnt_logged_in=False,
            messages=[],
            private_info="",
            user_descriptions=[],
            user_emails=[],
            user_public_keys=[],
        ))
        return

    user_emails_descs_pub_keys = db.get_user_emails_descs_pub_keys()

    client.conn.send(FetchResponse(
        is_success=True,
        isnt_logged_in=False,
        messages=[message.decode("utf-8") for message in db_user.messages],
        private_info=db_user.private_info.decode("utf-8"),
        user_emails=[user[0].string for user in user_emails_descs_pub_keys],
        user_descriptions=[user[1] for user in user_emails_descs_pub_keys],
        user_public_keys=[str(user[2].value) for user in user_emails_descs_pub_keys],
    ))

def handle_push_request(db: Database, client: Client, request: PushRequest):
    if client._logged_into_email is None:
        client.conn.send(PushResponse(is_succees=False, isnt_logged_in=True))
        return

    try:
        db_user = db.get_user(client._logged_into_email)
        db_user.private_info = request.private_info.encode("utf-8")
        db_user.messages = [m.encode("utf-8") for m in request.messages]
        db.insert_user(email=client._logged_into_email, value=db_user, should_already_exist=True)

        client.conn.send(PushResponse(is_succees=True, isnt_logged_in=False))
    except:
        client.conn.send(PushResponse(is_succees=False, isnt_logged_in=False))


def handle_send_request(db: Database, client: Client, request: SendRequest):
    if client._logged_into_email is None:
        client.conn.send(SendResponse(is_succees=False, invalid_email=False, user_doesnt_exist=False, not_logged_in=True))
        return

    try:
        target_email = Email(request.target_email)
        db_user = db.get_user(target_email)
    except InvalidEmailError:
        client.conn.send(SendResponse(is_succees=False, user_doesnt_exist=False, invalid_email=True, not_logged_in=False))
        return
    except:
        client.conn.send(SendResponse(is_succees=False, user_doesnt_exist=True, invalid_email=False, not_logged_in=False))
        return

    db_user.messages.append(request.content.encode("utf-8"))
    db.insert_user(target_email, db_user, should_already_exist=True)

    client.conn.send(SendResponse(is_succees=True, invalid_email=False, user_doesnt_exist=False, not_logged_in=False))

def handle_item_request(db: Database, client: Client, request: ItemRequest):
    try:
        id = Uuid(request.id)
        auth_key = Key(request.auth_key)
        db_auth_key = db.get_item_auth_key(id)
    except:
        client.conn.send(ItemResponse(
            is_success=False,
            wrong_key=False,
            contents="",
            release_key_contents=[]
        ))
        return

    if auth_key.hash() != db_auth_key:
        client.conn.send(ItemResponse(
            is_success=False,
            wrong_key=True,
            contents="",
            release_key_contents=[]
        ))
        return

    db_item = db.get_item(id)

    client.conn.send(ItemResponse(
        is_success=True,
        wrong_key=False,
        contents=db_item.contents.decode("utf-8"),
        release_key_contents=[release_key.info.decode("utf-8") for release_key in db_item.release_keys]
    ))

def handle_create_item_request(db: Database, client: Client, request: CreateItemRequest):
    try:
        auth_key = Key(request.auth_key)
        id = uuid4()
    except:
        client.conn.send(CreateItemResponse(is_success=False, id=""))
        return

    db.insert_item(id, Item(auth_key=auth_key.hash(), contents=request.contents.encode("utf-8"), release_keys=[]), should_already_exist=False)

    client.conn.send(CreateItemResponse(is_success=True, id=str(id)))

def handle_encrypt_item_request(db: Database, client: Client, request: EncryptItemRequest):
    try:
        id = Uuid(request.id)
        auth_key = Key(request.auth_key)
        db_auth_key = db.get_item_auth_key(id)
    except:
        client.conn.send(EncryptItemResponse(
            is_success=False,
            wrong_key=False,
        ))
        return

    if auth_key.hash() != db_auth_key:
        client.conn.send(EncryptItemResponse(
            is_success=False,
            wrong_key=True,
        ))
        return

    db_item = db.get_item(id)
    prefix = request.prefix.encode("utf-8")
    encrypted = encrypt(db_item.contents, request.public_key)
    db_item.contents = prefix + encrypted
    db.insert_item(id, db_item, should_already_exist=True)

    client.conn.send(EncryptItemResponse(
        is_success=True,
        wrong_key=False,
    ))

def handle_release_item_request(db: Database, client: Client, request: ReleaseItemRequest):
    try:
        id = Uuid(request.id)
        auth_key = Key(request.auth_key)
        db_auth_key = db.get_item_auth_key(id)
    except:
        client.conn.send(ReleaseItemResponse(
            is_success=False,
            wrong_key=False,
        ))
        return

    if auth_key.hash() != db_auth_key:
        client.conn.send(ReleaseItemResponse(
            is_success=False,
            wrong_key=True,
        ))
        return

    db_item = db.get_item(id)
    from datetime import datetime
    expires = datetime.fromisoformat(request.expires)
    db_item.release_keys.append(ReleaseKey(info=request.info.encode("utf-8"), expires=expires))
    db.insert_item(id, db_item, should_already_exist=True)

    client.conn.send(ReleaseItemResponse(
        is_success=True,
        wrong_key=False,
    ))