from dataclasses import dataclass
from typing import Literal

@dataclass
class LoginRequest:
    type: Literal["logic_request"]
    email: str
    auth_key: int

@dataclass
class UserRequest:
    type: Literal["user_request"]

@dataclass
class DeleteMessagesRequest:
    type: Literal["delete_messages_request"]

@dataclass
class ItemRequest:
    type: Literal["item_request"]
    id: bytes
    auth_key: int

Request = LoginRequest | UserRequest | DeleteMessagesRequest | ItemRequest
