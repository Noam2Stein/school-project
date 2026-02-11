from dataclasses import dataclass
from typing import Literal
from datetime import datetime

# A request from a client to create a new user.
@dataclass
class SignupRequest:
    type: Literal["SignupRequest"]
    # the email they want to signup as.
    email: str
    # A hash of a key derived from the user's password on the client side. This
    # will then be hashed again by the server then stored on the database to use
    # for comparison on each attempt to login.
    auth_key: int

# The server's response to `SignupRequest`.
@dataclass
class SignupResponse:
    type: Literal["SignupResponse"]
    # Was the signup succesful?
    is_succees: bool
    # `true` if the email is already taken. Its possible to have a failure where
    # this is false, where the cause is unknown.
    email_is_taken: bool

# A request from a client to login as a user.
@dataclass
class LoginRequest:
    type: Literal["LoginRequest"]
    # the email they want to login as.
    email: str
    # A hash of a key derived from the user's password on the client side. This
    # will then be hashed again by the server then compared to another hash
    # thats stored in the database.
    auth_key: int

# The server's response to `LoginRequest`.
@dataclass
class LoginResponse:
    type: Literal["LoginResponse"]
    # Was the login succesful?
    is_succees: bool
    # `true` if the password was correct. Its possible that the password was
    # correct but the login still failed because of an unknown server issue and
    # thats why the seperation of flags.
    password_is_correct: bool

# A client request to fetch information both about their logged in to user and
# general information.
@dataclass
class FetchRequest:
    type: Literal["FetchRequest"]

# The server's response to `FetchRequest`.
@dataclass
class FetchResponse:
    type: Literal["FetchResponse"]
    # The user's private information in an encrypted form where the format is
    # specified by the client.
    private_info: bytes
    # A list of encrypted messages sent to the user. Format is specified by the
    # client.
    messages: list[bytes]
    # A list of all user emails that use the app.
    user_emails: list[str]
    # A list of all user descriptions that use the app in the order matching `user_emails`.
    user_descriptions: list[str]
    # The public keys of all users in the order matching `user_emails`. The
    # public key of a user is used to send messages to that user.
    user_public_keys: list[bytes]


# A client request to push information on the user onto the server.
@dataclass
class PushRequest:
    type: Literal["PushRequest"]
    # The user's private information in an encrypted form where the format is
    # specified by the client.
    private_info: bytes
    # A list of encrypted messages sent to the user. Format is specified by the
    # client. When pushing, this is often empty because the client already
    # proccesed the messages and put the result in `private_info`.
    messages: list[bytes]

# The server's response to `PushRequest`.
@dataclass
class PushResponse:
    type: Literal["PushResponse"]
    # Was it succesful. If not, its important to send again.
    is_succees: bool

# A client request to send a message to another user via the server.
@dataclass
class SendRequest:
    type: Literal["SendRequest"]
    # The email of the user that should get the message.
    target_email: str
    # the message in a format encrypted using the user's public key. The
    # contents should be limited (enforced by the server) to a relatively small
    # size (this is not a messanging app).
    content: bytes

# The server's response to `SendRequest`.
@dataclass
class SendResponse:
    type: Literal["SendResponse"]
    # Was it succesful. If not, its important to send again.
    is_succees: bool

# A request to get the contents and metadata about a certain "item"
# (See `database::Item`).
@dataclass
class ItemRequest:
    type: Literal["ItemRequest"]
    # The item ID.
    id: bytes
    # A key used to make sure the user has access to the item. This is later
    # hashed on the server and compared to another key from the database.
    auth_key: int

# The server's response to `ItemRequest`.
@dataclass
class ItemResponse:
    type: Literal["ItemResponse"]
    # Is it succesful.
    is_success: bool
    # Did the request fail because authentication fail? If not, the error is
    # unknown.
    wrong_key: bool
    # The contents of the item in an unknown encrypted format thats specified by
    # client code. This may be megabytes long.
    contents: bytes
    # The item's release keys's contents. See `database::ReleaseKey`.
    release_key_contents: list[bytes]

# A request to create a new item.
@dataclass
class CreateItemRequest:
    type: Literal["CreateItemRequest"]
    # The contents of the item in encrytped form. The format is specified only
    # in client code.
    contents: bytes
    # The origin of the authentication key in `ItemRequest`.
    auth_key: int

# The server's response to `CreateItemRequest`.
@dataclass
class CreateItemResponse:
    type: Literal["CreateItemResponse"]
    # Is it succesful.
    is_success: bool
    # The ID of the item later used in `ItemRequest`.
    id: bytes

# A request from a client to the server to take the item, encrypt it using a
# public key, and add a prefix to it, and store the result in the place of the
# old contents on the database. Where the resulting contents of the item
# are `prefix + encrypted(the_old_contents, the_public_key)`.
@dataclass
class EncryptItemRequest:
    type: Literal["EncryptItemRequest"]
    # The ID of the item to encrypt.
    id: bytes
    # Used to ensure that the client has permissions to encrypt the item.
    # See `ItemRequest::auth_key`.
    auth_key: int
    # The public key used to encrypt the item.
    public_key: bytes
    # The prefix that should be added to the item after its encrypted.
    prefix: bytes

# The server's response to `EncryptItemRequest`.
@dataclass
class EncryptItemResponse:
    type: Literal["EncryptItemResponse"]
    # Is it succesful.
    is_success: bool
    # Did it fail because the `auth_key` is wrong. If this is false and
    # `is_success` is false, there was an unknown error and the client should
    # try again.
    wrong_key: bool

# A request from a client to the server to store a new release key for a given
# item. This means that the user wants to release their lock on an item's
# encryption.
@dataclass
class ReleaseItemRequest:
    type: Literal["ReleaseItemRequest"]
    # The ID of the item to release.
    id: bytes
    # Used to ensure that the client has permissions to the item.
    # See `ItemRequest::auth_key`.
    auth_key: int
    # The contents of the release key to be used by client code. Format is
    # unspeficied to the server.
    info: bytes
    # When should the server delete the release key?
    expires: datetime

# The server's response to `ReleaseItemRequest`.
@dataclass
class ReleaseItemResponse:
    type: Literal["ReleaseItemResponse"]
    # Is it succesful.
    is_success: bool

Request = SignupRequest | LoginRequest | FetchRequest | PushRequest | SendRequest | ItemRequest | CreateItemRequest | EncryptItemRequest | ReleaseItemRequest
Response = SignupResponse | LoginResponse | FetchResponse | PushResponse | SendResponse | ItemResponse | CreateItemResponse | EncryptItemResponse | ReleaseItemResponse
