import sqlite3
import pickle
from dataclasses import dataclass
from datetime import datetime
from threading import Lock
from uuid import UUID as Uuid

from lib.key import Key
from lib.email import Email

# Information stored about each user in the database. This type only contains
# data and is not a database handle.
@dataclass
class User:
    # This is the result of a key derived from the user's password which is
    # encrypted once on the client then encrytped again on the server. If the
    # client has given a key that results in this, they are authenticated to
    # access the user's account.
    auth_key: Key
    # Information private to the user. This is in encrypted form and the format
    # is only specified in client code.
    private_info: bytes
    # The public key used to send messages to the user.
    public_key: Key
    # A list of messages sent to the user that were encryted using `public_key`.
    messages: list[bytes]
    # A publicly available description of the user so that my sql databse uses
    # foreign keys (the teacher asked for it).
    description: str

# A release key is a piece of information that can be used to release a single
# lock on an item (a lock that was enabled by one of the users). The information
# is encrypted and the format is only specified in client code. This type only
# contains data and is not a database handle.
@dataclass
class ReleaseKey:
    # the stored information that clients can request.
    info: bytes
    # a certain time where the key should be deleted by the server. This is
    # something the client can request from the server to set up.
    expires: datetime

# an item is a piece of information encrypted by a group of users. The server
# doesn't know what users relate to which items. This type only contains data
# and is not a database handle.
@dataclass
class Item:
    # a key that is used to ensure that a client has permission to an item. Its
    # the client's job to give this key each time they want to access the item,
    # then the server hashes it and compared it to this key from the database.
    auth_key: Key
    # the encrypted contents of the item. The format of this is only specified
    # in client code. Its important to remember that this piece of information
    # may be very large (a large encrpted file for example).
    contents: bytes
    # a list of the item's release keys (read the docs for `ReleaseKey`).
    release_keys: list[ReleaseKey]

# A handle to the database. Do not create multiple instances of this type at the
# same time. You can safely call methods of this type from multiple threads at
# the same time.
class Database:
    def __init__(self, data_dir: str):
        self._data_dir = data_dir
        
        sqlite_path = f"{self._data_dir}/.sqlite"
        self._conn = sqlite3.connect(sqlite_path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON;")
        self._cursor = self._conn.cursor()

        is_new_database = not self._cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        ).fetchone()

        if is_new_database:
            self._cursor.execute(
                """
                CREATE TABLE users (
                    email TEXT PRIMARY KEY,
                    auth_key BLOB,
                    private_info BLOB,
                    public_key BLOB,
                    messages BLOB
                );
                """
            )
            self._cursor.execute(
                """
                CREATE TABLE items (
                    id TEXT PRIMARY KEY,
                    auth_key BLOB,
                    contents BLOB,
                    release_keys BLOB
                );
                """
            )
            self._cursor.execute(
                """
                CREATE TABLE user_descriptions (
                    email TEXT PRIMARY KEY REFERENCES users(email) ON DELETE CASCADE,
                    description TEXT
                );
                """
            )
            self._conn.commit()

        self._lock = Lock()
    
    # creates a user. If this function fails (user should already exist but
    # doesn't, or the opposite) the database is kept as it was before and the
    # function panics.
    def insert_user(self, email: Email, value: User, should_already_exist: bool):
        with self._lock:
            self._cursor.execute(
                """
                SELECT auth_key FROM users WHERE email = ?
                """,
                (email.string,),
            )
            if should_already_exist and self._cursor.fetchone() is None:
                raise Exception(f"user {email} doesn't exist")
            elif not should_already_exist and self._cursor.fetchone() is not None:
                raise Exception(f"user {email} already exists")
            
            self._cursor.execute(
                """
                INSERT OR REPLACE INTO users (email, auth_key, private_info, public_key, messages) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    email.string,
                    value.auth_key.value.to_bytes(32),
                    value.private_info,
                    value.public_key.value.to_bytes(32),
                    pickle.dumps(value.messages),
                ),
            )
            self._cursor.execute(
                """
                INSERT OR REPLACE INTO user_descriptions (email, description) VALUES (?, ?)
                """,
                (
                    email.string,
                    value.description,
                ),
            )
            self._conn.commit()

    # inserts an "item". If this function fails (item should already exist but
    # doesn't, or the opposite) the database is kept as it was before and the
    # function panics.
    def insert_item(self, id: Uuid, value: Item, should_already_exist: bool):
        with self._lock:
            self._cursor.execute(
                """
                SELECT auth_key FROM items WHERE id = ?
                """,
                (id.bytes,),
            )
            if should_already_exist and self._cursor.fetchone() is None:
                raise Exception(f"item {id} doesn't exist")
            elif not should_already_exist and self._cursor.fetchone() is not None:
                raise Exception(f"item {id} already exists")
            
            self._cursor.execute(
                """
                INSERT OR REPLACE INTO items (id, auth_key, contents, release_keys) VALUES (?, ?, ?, ?)
                """,
                (
                    id.bytes,
                    value.auth_key.value.to_bytes(32),
                    value.contents,
                    pickle.dumps(value.release_keys),
                ),
            )
            self._conn.commit()
    
    # Returns information stored about a user. If this function panics you can
    # guess that the user doesn't exist.
    def get_user(self, email: Email) -> User:
        with self._lock:
            self._cursor.execute(
                """
                SELECT auth_key, private_info, public_key, messages FROM users WHERE email = ?
                """,
                (email.string,),
            )
            value = self._cursor.fetchone()
            if value is None:
                raise Exception(f"user {email} doesn't exist")

            self._cursor.execute(
                """
                SELECT description FROM user_descriptions WHERE email = ?
                """,
                (email.string,),
            )
            description_value = self._cursor.fetchone()

            return User(
                auth_key=Key(int.from_bytes(value["auth_key"])),
                private_info=value["private_info"],
                public_key=Key(int.from_bytes(value["public_key"])),
                messages=pickle.loads(value["messages"]),
                description=description_value["description"],
            )
    
    # Returns information stored about an item. If this function panics, the
    # item doesn't exist. The result of this function contains the actual data
    # of the item, which may be megabytes long. To exclude the actual item data,
    # use `get_item_metadata`.
    def get_item(self, id: Uuid) -> Item:
        with self._lock:
            self._cursor.execute(
                """
                SELECT auth_key, contents, release_keys FROM items WHERE id = ?
                """,
                (id.bytes,),
            )
            value = self._cursor.fetchone()
            if value is None:
                raise Exception(f"item {id} doesn't exist")
            
            return Item(
                auth_key=Key(int.from_bytes(value["auth_key"])),
                contents=value["contents"],
                release_keys=pickle.loads(value["release_keys"]),
            )

    # Returns information stored about an item excluding the contents. If this
    # function panics, the item doesn't exist. "contents" are the actual data
    # of the item which may be megabytes long.
    def get_item_metadata(self, id: Uuid) -> Item:
        with self._lock:
            self._cursor.execute(
                """
                SELECT auth_key, release_keys FROM items WHERE id = ?
                """,
                (id.bytes,),
            )
            value = self._cursor.fetchone()
            if value is None:
                raise Exception(f"item {id} doesn't exist")
            
            return Item(
                auth_key=Key(int.from_bytes(value["auth_key"])),
                contents=bytes(),
                release_keys=pickle.loads(value["release_keys"]),
            )

    # Removes the info about a user from the database. This function does not
    # panic if the user doesn't exist.
    def remove_user(self, email: Email):
        with self._lock:
            self._cursor.execute(
                """
                DELETE FROM users WHERE email = ?
                """,
                (email.string,),
            )
            self._conn.commit()
    
    # Removes info about an item from the database. This function does not
    # panic if the item doesn't exist.
    def remove_item(self, id: Uuid):
        with self._lock:
            self._cursor.execute(
                """
                DELETE FROM items WHERE id = ?
                """,
                (id.bytes,),
            )
            self._conn.commit()
