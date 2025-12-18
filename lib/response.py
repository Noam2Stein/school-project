from dataclasses import dataclass
from typing import Literal

from lib import database

@dataclass
class LoginResponse:
    type: Literal["logic_response"]
    is_successful: bool
    error_message: str

@dataclass
class UserResponse:
    type: Literal["user_response"]
    items: bytes
    messages: list[bytes]

@dataclass
class ItemResponse:
    type: Literal["item_response"]
    contents: bytes
    release_keys: list[database.ReleaseKey]

Response = LoginResponse | UserResponse
