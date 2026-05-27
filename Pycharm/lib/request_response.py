from dataclasses import dataclass
from typing import Literal
from lib.encryption import PublicKey


# A request from a client to create a new user.
@dataclass
class SignupRequest:
    # the email they want to signup as.
    email: str
    # A hash of a key derived from the user's password on the client side. This
    # will then be hashed again by the server then stored on the database to use
    # for comparison on each attempt to login.
    auth_key: str
    # The user's private information in an encrypted form where the format is
    # specified by the client. This would be of type `bytes` but json serialization
    # does not support bytes.
    private_info: str
    # the public key of the user used to send them encrypted messages.
    public_key: PublicKey
    # A description of the user.
    description: str = ""
    type: Literal["SignupRequest"] = "SignupRequest"


# The server's response to `SignupRequest`.
@dataclass
class SignupResponse:
    # Was the signup successful?
    is_success: bool
    # `true` if the email is already taken. It's possible to have a failure where
    # this is false, where the cause is unknown.
    email_is_taken: bool
    type: Literal["SignupResponse"] = "SignupResponse"


# A request from a client to login as a user.
@dataclass
class LoginRequest:
    # the email they want to log in as.
    email: str
    # A hash of a key derived from the user's password on the client side. This
    # will then be hashed again by the server then compared to another hash
    # that is stored in the database.
    auth_key: str
    type: Literal["LoginRequest"] = "LoginRequest"


# The server's response to `LoginRequest`.
@dataclass
class LoginResponse:
    # Was the login successful?
    is_success: bool
    # `true` is the request failed because of an incorrect password.
    incorrect_password: bool
    # `true` if the user doesn't exist.
    user_doesnt_exist: bool
    type: Literal["LoginResponse"] = "LoginResponse"


# A client request to fetch information both about their logged in to user and
# general information.
@dataclass
class FetchRequest:
    type: Literal["FetchRequest"] = "FetchRequest"


# The server's response to `FetchRequest`.
@dataclass
class FetchResponse:
    # is it a success...
    is_success: bool
    # did the request fail because the client isn't logged in.
    not_logged_in: bool
    # The user's private information in an encrypted form where the format is
    # specified by the client. This would be `bytes` but they are not supported by json.
    private_info: str
    # A list of encrypted messages sent to the user. Format is specified by the
    # client. This would be `bytes` but they are not supported by json.
    messages: list[str]
    # A list of all user emails that use the app.
    user_emails: list[str]
    # A list of all user descriptions that use the app in the order matching `user_emails`.
    user_descriptions: list[str]
    # The public keys of all users in the order matching `user_emails`. The
    # public key of a user is used to send messages to that user.
    user_public_keys: list[PublicKey]
    type: Literal["FetchResponse"] = "FetchResponse"


# A client request to push information on the user onto the server.
@dataclass
class PushRequest:
    # The user's private information in an encrypted form where the format is
    # specified by the client.
    # This would be `bytes` but they are not supported by json.
    private_info: str
    # A list of encrypted messages sent to the user. Format is specified by the
    # client. When pushing, this is often empty because the client already
    # processed the messages and put the result in `private_info`.
    # This would be `bytes` but they are not supported by json.
    messages: list[str]
    type: Literal["PushRequest"] = "PushRequest"


# The server's response to `PushRequest`.
@dataclass
class PushResponse:
    # Was it successful. If not, it is important to send again.
    is_success: bool
    # did the request fail because the client isn't logged in.
    not_logged_in: bool
    type: Literal["PushResponse"] = "PushResponse"


# A client request to send a message to another user via the server.
@dataclass
class SendRequest:
    # The email of the user that should get the message.
    target_email: str
    # the message in a format encrypted using the user's public key. The
    # contents should be limited (enforced by the server) to a relatively small
    # size (this is not a messaging app).
    # This would be `bytes` but they are not supported by json.
    content: str
    type: Literal["SendRequest"] = "SendRequest"


# The server's response to `SendRequest`.
@dataclass
class SendResponse:
    # Was it successful. If not, its important to send again.
    is_success: bool
    invalid_email: bool
    user_doesnt_exist: bool
    not_logged_in: bool
    type: Literal["SendResponse"] = "SendResponse"


# A request to get the contents and metadata about a certain "item"
# (See `database::Item`).
@dataclass
class ItemRequest:
    # The item ID.
    # This would be `bytes` but they are not supported by json.
    id: str
    # A key used to make sure the user has access to the item. This is later
    # hashed on the server and compared to another key from the database.
    auth_key: str
    type: Literal["ItemRequest"] = "ItemRequest"


# The server's response to `ItemRequest`.
@dataclass
class ItemResponse:
    # Is it successful.
    is_success: bool
    # Did the request fail because authentication fail? If not, the error is
    # unknown.
    wrong_key: bool
    # The contents of the item in an unknown encrypted format thats specified by
    # client code. This may be megabytes long.
    # This would be `bytes` but they are not supported by json.
    contents: str
    # The item's release keys contents. See `database::ReleaseKey`.
    # This would be `bytes` but they are not supported by json.
    release_key_contents: list[str]
    type: Literal["ItemResponse"] = "ItemResponse"


# A request to create a new item.
@dataclass
class CreateItemRequest:
    # The contents of the item in encrypted form. The format is specified only
    # in client code.
    # This would be `bytes` but they are not supported by json.
    contents: str
    # The origin of the authentication key in `ItemRequest`.
    auth_key: str
    type: Literal["CreateItemRequest"] = "CreateItemRequest"


# The server's response to `CreateItemRequest`.
@dataclass
class CreateItemResponse:
    # Is it successful.
    is_success: bool
    # The ID of the item later used in `ItemRequest`.
    # This would be `bytes` but they are not supported by json.
    id: str
    type: Literal["CreateItemResponse"] = "CreateItemResponse"


# A request from a client to the server to take the item, encrypt it using a
# public key, and add a prefix to it, and store the result in the place of the
# old contents on the database. Where the resulting contents of the item
# are `prefix + encrypted(the_old_contents, the_public_key)`.
@dataclass
class EncryptItemRequest:
    # The ID of the item to encrypt.
    # This would be `bytes` but they are not supported by json.
    id: str
    # Used to ensure that the client has permissions to encrypt the item.
    # See `ItemRequest::auth_key`.
    auth_key: str
    # The public key used to encrypt the item.
    # This would be `bytes` but they are not supported by json.
    public_key: PublicKey
    # The prefix that should be added to the item after its encrypted.
    # This would be `bytes` but they are not supported by json.
    prefix: str
    type: Literal["EncryptItemRequest"] = "EncryptItemRequest"


# The server's response to `EncryptItemRequest`.
@dataclass
class EncryptItemResponse:
    # Is it successful.
    is_success: bool
    # Did it fail because the `auth_key` is wrong. If this is false and
    # `is_success` is false, there was an unknown error and the client should
    # try again.
    wrong_key: bool
    type: Literal["EncryptItemResponse"] = "EncryptItemResponse"


# A request from a client to the server to store a new release key for a given
# item. This means that the user wants to release their lock on an item's
# encryption.
@dataclass
class ReleaseItemRequest:
    # The ID of the item to release.
    # This would be `bytes` but they are not supported by json.
    id: str
    # Used to ensure that the client has permissions to the item.
    # See `ItemRequest::auth_key`.
    auth_key: str
    # The contents of the release key to be used by client code. Format is
    # unspecified to the server.
    # This would be `bytes` but they are not supported by json.
    info: str
    # When should the server delete the release key?
    # ISO 8601 string (datetime is not JSON serializable).
    expires: str
    type: Literal["ReleaseItemRequest"] = "ReleaseItemRequest"


# The server's response to `ReleaseItemRequest`.
@dataclass
class ReleaseItemResponse:
    # Is it successful.
    is_success: bool
    # Did it fail because the `auth_key` is wrong. If this is false and
    # `is_success` is false, there was an unknown error and the client should
    # try again.
    wrong_key: bool
    type: Literal["ReleaseItemResponse"] = "ReleaseItemResponse"


Request = SignupRequest | LoginRequest | FetchRequest | PushRequest | SendRequest | ItemRequest \
          | CreateItemRequest | EncryptItemRequest | ReleaseItemRequest
Response = SignupResponse | LoginResponse | FetchResponse | PushResponse \
           | SendResponse | ItemResponse | CreateItemResponse | EncryptItemResponse | ReleaseItemResponse
