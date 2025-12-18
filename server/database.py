from dataclasses import dataclass
from uuid import UUID as Uuid
from datetime import datetime

from shared.email import Email
from shared.key import Key, KeyHash

class User:
    """
    A mutable handle to a user.
    Any mutations are automatically applied to the database.

    A user has:
    - `key_hash` is the expected key hash of the user's provided key used for authentication.
    - `items` is an encrypted list of the user's items with an unknown format.
    - `public_key` is the public key used to send messages to the user.
    - `messages` is a list of encrypted messages sent to this user which have an unknown
      format and were encrypted with `public_key`.
    """

    def __init__(self):
        raise RuntimeError("to access a user, use `Database`")

    @property
    def key_hash(self) -> KeyHash:
        raise RuntimeError("TODO")
    
    @key_hash.setter
    def set_key_hash(self, key: KeyHash):
        raise RuntimeError("TODO")
    
    @property
    def items(self) -> bytes:
        raise RuntimeError("TODO")
    
    @items.setter
    def set_items(self, items: bytes):
        raise RuntimeError("TODO")
    
    @property
    def public_key(self) -> Key:
        raise RuntimeError("TODO")
    
    @public_key.setter
    def set_public_key(self, key: Key):
        raise RuntimeError("TODO")
    
    @property
    def messages(self) -> list[bytes]:
        raise RuntimeError("TODO")
    
    @messages.setter
    def set_messages(self, messages: list[bytes]):
        raise RuntimeError("TODO")
    
class Item:
    """
    A mutable handle to an item.
    Any mutations are automatically applied to the database.

    An item has:
    - `data` is the encrypted data of the item which has an unknown format.
    """

    def __init__(self):
        raise RuntimeError("to access an item, use `Database`")
    
    @property
    def data(self) -> bytes:
        raise RuntimeError("TODO")
    
    @data.setter
    def set_data(self, data: bytes):
        raise RuntimeError("TODO")

@dataclass
class ReleaseKey:
    """
    The value of a release key.

    - `key` is the encrypted release key, meaning you need another key to decrypt it.
    - `expires` the datetime where we are asked to delete the release key.

    This is not a mutable handle to a release key, any mutations should be submitted
    through `Database.set_release_key`.
    """

    key: bytes
    expires: datetime

class Database:
    """
    A mutable handle to a database.

    The database has:
    - users
    - items
    - release keys

    We intentionally do not know the relationship between these 3 until a user
    logs in and accesses them.
    """

    def __init__(self, dir: str):
        pass

    def add_user(self, email: Email, key: KeyHash) -> User:
        """
        Adds a new user and returns a mutable handle to it,
        or panics if the email is already in use.
        """

        raise RuntimeError("TODO")

    def get_user(self, email: Email) -> User:
        """
        Returns a mutable handle to a user or panics if the email is not found.
        """

        raise RuntimeError("TODO")
    
    def remove_user(self, email: Email):
        """
        Removes a user or panics if the email is not found.
        """

        raise RuntimeError("TODO")
    
    def add_item(self, uuid: Uuid, key: KeyHash, data: bytes) -> Item:
        """
        Adds a new item and returns a mutable handle to it,
        or panics if the uuid is already in use.
        """

        raise RuntimeError("TODO")
    
    def get_item(self, uuid: Uuid) -> Item:
        """
        Returns a mutable handle to an item or panics if the uuid is not found.
        """

        raise RuntimeError("TODO")
    
    def remove_item(self, uuid: Uuid):
        """
        Removes an item or panics if the uuid is not found.
        """

        raise RuntimeError("TODO")
    
    def add_release_key(self, id: Uuid, value: ReleaseKey):
        """
        Adds a new release key or panics if the uuid is already in use.
        """

        raise RuntimeError("TODO")
    
    def get_release_key(self, id: Uuid) -> ReleaseKey:
        """
        Returns the value of a release key or panics if the uuid is not found.
        """

        raise RuntimeError("TODO")
    
    def set_release_key(self, id: Uuid, value: ReleaseKey):
        """
        Sets the value of a release key or panics if the uuid is not found.
        """

        raise RuntimeError("TODO")
    
    def remove_release_key(self, id: Uuid):
        """
        Removes a release key or panics if the uuid is not found.
        """

        raise RuntimeError("TODO")
    
    def get_release_key_ids(self) -> list[Uuid]:
        """
        Returns the ids of all release keys.
        """

        raise RuntimeError("TODO")
