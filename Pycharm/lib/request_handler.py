from .socket_wrapper import ServerConnection
from .database import Database, User, Item, ReleaseKey
from .request_response import *
from .email import Email
from .key import Key
from .encryption import encrypt
from uuid import UUID as Uuid, uuid4

class Client:
    _conn: ClientConnection
    _logged_into_email: Email | None

    def __init__(self, conn: ServerConnection):
        self._conn = conn

def handle_next_request(db: Database, client: Client):
    request = client._conn.recv()
    while request is None:
        request = client._conn.recv()

    if request.type == "SignupRequest":
        handle_signup_request(client, request)
    if request.type == "LoginRequest":
        handle_login_request(client, request)
    if request.type == "FetchRequest":
        handle_fetch_request(client, request)
    if request.type == "PushRequest":
        handle_push_request(client, request)
    if request.type == "SendRequest":
        handle_send_request(client, request)
    if request.type == "ItemRequest":
        handle_item_request(client, request)
    if request.type == "CreateItemRequest":
        handle_create_item_request(client, request)
    if request.type == "EncryptItemRequest":
        handle_encrypt_item_request(client, request)
    if request.type == "ReleaseItemRequest":
        handle_release_item_request(client, request)

    pass

def handle_signup_request(db: Database, client: Client, request: SignupRequest):
    try:
        email = Email(request.email)
        auth_key = Key(request.auth_key)
    except:
        client._conn.send(SignupResponse(is_succees=False,email_is_taken=False))
        return

    if db.has_user(email=email):
        client._conn.send(SignupResponse(is_succees=False,email_is_taken=True))
        return

    db.insert_user(
        email,
        User(
            auth_key=auth_key,
            private_info=request.private_info,
            public_key=request.public_key
        )
    )
    client._logged_into_email = email
    client._conn.send(SignupResponse(is_succees=True,email_is_taken=False))

def handle_login_request(db: Database, client: Client, request: LoginRequest):
    try:
        email = Email(request.email)
        auth_key = Key(request.auth_key)
    except:
        client._conn.send(LoginResponse(is_succees=False,incorrect_password=False,user_doesnt_exist=False))
        return

    if not db.has_user(email=email):
        client._conn.send(LoginResponse(is_succees=False,incorrect_password=False,user_doesnt_exist=True))
        return

    db_auth_key = db.get_user_auth_key(email)
    if auth_key != db_auth_key:
        client._conn.send(LoginResponse(is_succees=False,incorrect_password=True,user_doesnt_exist=False))
        return

    # Its bad practice to make the authentication success branch the normal
    # branch and the failure branch with early returns, but its very funny and
    # this is not a serious project so fuck it.

    client._logged_into_email = email
    client._conn.send(LoginResponse(is_succees=True,incorrect_password=False,user_doesnt_exist=False))

def handle_fetch_request(db: Database, client: Client, request: FetchRequest):
    if client._logged_into_email is None:
        client._conn.send(FetchResponse(
            is_success=False,
            isnt_logged_in=True,
            messages=[],
            private_info=bytes(),
            user_descriptions=[],
            user_emails=[],
            user_public_keys=[],
        ))
        return

    try:
        db_user = db.get_user(client._logged_into_email)
    except:
        client._conn.send(FetchResponse(
            is_success=False,
            isnt_logged_in=False,
            messages=[],
            private_info=bytes(),
            user_descriptions=[],
            user_emails=[],
            user_public_keys=[],
        ))
        return

    user_emails_descs_pub_keys = db.get_user_emails_descs_pub_keys()
    
    client._conn.send(FetchResponse(
        is_success=True,
        isnt_logged_in=False,
        messages=db_user.messages,
        private_info=db_user.private_info,
        user_emails=[user[0].string() for user in user_emails_descs_pub_keys],
        user_descriptions=[user[1] for user in user_emails_descs_pub_keys],
        user_public_keys=[user[0].string() for user in user_emails_descs_pub_keys],
    ))

def handle_push_request(db: Database, client: Client, request: PushRequest):
    if client._logged_into_email is None:
        client._conn.send(PushResponse(is_succees=False, isnt_logged_in=True))
        return

    try:
        db_user = db.get_user(client._logged_into_email)
        db_user.private_info = request.private_info
        db_user.messages = request.messages
        db.insert_user(email=client._logged_into_email, value=db_user, should_already_exist=True)
        
        client._conn.send(PushResponse(is_succees=True, isnt_logged_in=False))
    except:
        client._conn.send(PushResponse(is_succees=False, isnt_logged_in=False))


def handle_send_request(db: Database, client: Client, request: SendRequest):
    if client._logged_into_email is None:
        client._conn.send(SendResponse(is_succees=False))
        return

    try:
        target_email = Email(request.target_email)
        db_user = db.get_user(target_email)
    except:
        client._conn.send(SendResponse(is_succees=False))
        return

    db_user.messages.append(request.content)
    db.insert_user(target_email, db_user)

    client._conn.send(SendResponse(is_succees=True))

def handle_item_request(db: Database, client: Client, request: ItemRequest):
    try:
        id = Uuid.from_bytes(request.id)
        auth_key = Key(request.auth_key)
        db_auth_key = db.get_item_auth_key(id)
    except:
        client._conn.send(ItemResponse(
            is_succees=False,
            wrong_key=False,
            contents=bytes(),
            release_key_contents=[]
        ))
        return

    if auth_key.hash() != db_auth_key:
        client._conn.send(ItemResponse(
            is_succees=False,
            wrong_key=True,
            contents=bytes(),
            release_key_contents=[]
        ))
        return

    db_item = db.get_item(id)

    client._conn.send(ItemResponse(
        is_succees=True,
        wrong_key=False,
        contents=db_item.contents,
        release_key_contents=[release_key.info for release_key in db_item.release_keys]
    ))
    return

def handle_create_item_request(db: Database, client: Client, request: CreateItemRequest):
    try:
        auth_key = Key(request.auth_key)
        id = uuid4()
    except:
        client._conn.send(CreateItemResponse(is_success=False,id=bytes()))
        return

    db.insert_item(id, Item(auth_key=auth_key,contents=request.contents,release_keys=[]))

    client._conn.send(CreateItemResponse(is_success=True,id=id.bytes))

def handle_encrypt_item_request(db: Database, client: Client, request: EncryptItemRequest):
    try:
        id = Uuid.from_bytes(request.id)
        auth_key = Key(request.auth_key)
        db_auth_key = db.get_item_auth_key(id)
    except:
        client._conn.send(EncryptItemResponse(
            is_succees=False,
            wrong_key=False,
        ))
        return

    if auth_key.hash() != db_auth_key:
        client._conn.send(EncryptItemResponse(
            is_succees=False,
            wrong_key=True,
        ))
        return

    db_item = db.get_item(id)
    contents = bytearray()
    contents.extend(request.prefix)
    contents.extend(encrypt(db_item.contents,request.public_key))
    db_item.contents = contents
    db.insert_item(id, db_item, should_already_exist=True)

    client._conn.send(EncryptItemResponse(
        is_succees=True,
        wrong_key=False,
    ))
    return

def handle_release_item_request(db: Database, client: Client, request: ReleaseItemRequest):
    try:
        id = Uuid.from_bytes(request.id)
        auth_key = Key(request.auth_key)
        db_auth_key = db.get_item_auth_key(id)
    except:
        client._conn.send(ReleaseItemResponse(
            is_succees=False,
            wrong_key=False,
        ))
        return

    if auth_key.hash() != db_auth_key:
        client._conn.send(ReleaseItemResponse(
            is_succees=False,
            wrong_key=True,
        ))
        return

    db_item = db.get_item(id)
    db_item.release_keys.append(ReleaseKey(info=request.info,expires=request.expires))
    db.insert_item(id, db_item, should_already_exist=True)

    client._conn.send(ReleaseItemResponse(
        is_succees=True,
        wrong_key=False,
    ))
    return
