import sqlite3
import pickle
from dataclasses import dataclass
from datetime import datetime
from threading import Lock
from lib.email import Email
from lib.encryption import PublicKey
from lib.encode_default import bytes_to_str, str_to_bytes


# Information stored about each user in the database. This type only contains
# data and is not a database handle.
@dataclass
class User:
    # This is the result of a key derived from the user's password which is
    # encrypted once on the client then encrytped again on the server. If the
    # client has given a key that results in this, they are authenticated to
    # access the user's account.
    auth_key: str
    # Information private to the user. This is in encrypted form and the format
    # is only specified in client code.
    private_info: str
    # The public key used to send messages to the user.
    public_key: PublicKey
    # A list of messages sent to the user that were encryted using `public_key`.
    messages: list[str]
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
    info: str
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
    auth_key: str
    # the encrypted contents of the item. The format of this is only specified
    # in client code. Its important to remember that this piece of information
    # may be very large (a large encrpted file for example).
    contents: str
    # a list of the item's release keys (read the docs for `ReleaseKey`).
    release_keys: list[ReleaseKey]
    # The recursively encrypted locks chain next to contents
    locks: str = ""


# A handle to the database. Do not create multiple instances of this type at the
# same time. You can safely call methods of this type from multiple threads at
# the same time.
class Database:
    def __init__(self, data_dir: str):
        self._data_dir = data_dir
        
        sqlite_path = f"{self._data_dir}/.sqlite"
        self._conn = sqlite3.connect(sqlite_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON;")

        cursor = self._conn.cursor()

        is_new_database = not cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        ).fetchone()

        if is_new_database:
            cursor.execute(
                """
                CREATE TABLE users (
                    email TEXT PRIMARY KEY,
                    auth_key TEXT,
                    private_info TEXT,
                    public_key TEXT,
                    messages TEXT
                );
                """
            )
            cursor.execute(
                """
                CREATE TABLE items (
                    id TEXT PRIMARY KEY,
                    auth_key TEXT,
                    contents TEXT,
                    release_keys TEXT,
                    locks TEXT DEFAULT ''
                );
                """
            )
            cursor.execute(
                """
                CREATE TABLE user_descriptions (
                    email TEXT PRIMARY KEY REFERENCES users(email) ON DELETE CASCADE,
                    description TEXT
                );
                """
            )
            self._conn.commit()

        # Schema Migration: Add locks column to items if it doesn't exist on an existing database
        cursor = self._conn.cursor()
        columns = [row[1] for row in cursor.execute("PRAGMA table_info(items)").fetchall()]
        if "locks" not in columns:
            cursor.execute("ALTER TABLE items ADD COLUMN locks TEXT DEFAULT '';")
            self._conn.commit()

        self._lock = Lock()
    
    # creates a user. If this function fails (user should already exist but
    # doesn't, or the opposite) the database is kept as it was before and the
    # function panics.
    def insert_user(self, email: Email, value: User, should_already_exist: bool):
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT auth_key FROM users WHERE email = ?
                """,
                (email.string,),
            )
            fechedone = cursor.fetchone()
            if should_already_exist and fechedone is None:
                raise Exception(f"user {email} doesn't exist")
            elif not should_already_exist and fechedone is not None:
                raise Exception(f"user {email} already exists")
            
            cursor.execute(
                """
                INSERT OR REPLACE INTO users (email, auth_key, private_info, public_key, messages) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    email.string,
                    value.auth_key,
                    value.private_info,
                    str(value.public_key),
                    bytes_to_str(pickle.dumps(value.messages)),
                ),
            )
            cursor.execute(
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
    def insert_item(self, identifier: str, value: Item, should_already_exist: bool):
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT auth_key FROM items WHERE id = ?
                """,
                (identifier,),
            )
            result = cursor.fetchone()
            if should_already_exist and result is None:
                raise Exception(f"item {identifier} doesn't exist")
            elif not should_already_exist and result is not None:
                raise Exception(f"item {identifier} already exists")
            
            cursor.execute(
                """
                INSERT OR REPLACE INTO items (id, auth_key, contents, release_keys, locks) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    identifier,
                    value.auth_key,
                    value.contents,
                    bytes_to_str(pickle.dumps(value.release_keys)),
                    value.locks,
                ),
            )
            self._conn.commit()

    # returns true if the database has a user with the given email.
    def has_user(self, email: Email) -> bool:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT auth_key FROM users WHERE email = ?
                """,
                (email.string,),
            )
            value = cursor.fetchone()
            if value is None:
                return False
            else:
                return True

    # returns true if the database has an item with the given id.
    def has_item(self, identifier: str) -> bool:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT id FROM items WHERE id = ?
                """,
                (identifier,),
            )
            value = cursor.fetchone()
            if value is None:
                return False
            else:
                return True
    
    # Returns information stored about a user. If this function panics you can
    # guess that the user doesn't exist.
    def get_user(self, email: Email) -> User | None:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT auth_key, private_info, public_key, messages FROM users WHERE email = ?
                """,
                (email.string,),
            )
            value = cursor.fetchone()
            if value is None:
                return None

            cursor.execute(
                """
                SELECT description FROM user_descriptions WHERE email = ?
                """,
                (email.string,),
            )
            description_value = cursor.fetchone()

            return User(
                auth_key=value["auth_key"],
                private_info=value["private_info"],
                public_key=value["public_key"],
                messages=pickle.loads(str_to_bytes(value["messages"])),
                description=description_value["description"],
            )

    # returns the auth key of the given user or panics if the email doesn't
    # exist.
    def get_user_auth_key(self, email: Email) -> str | None:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT auth_key FROM users WHERE email = ?
                """,
                (email.string,),
            )
            user = cursor.fetchone()
            if user is None:
                return None

            return user["auth_key"]

    # returns the emails, descriptions, and public keys of all users in the database.
    def get_user_emails_descs_pub_keys(self) -> list[tuple[Email, str, PublicKey]]:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT users.email, user_descriptions.description, users.public_key
                FROM users
                JOIN user_descriptions
                    ON users.email = user_descriptions.email
                """
            )
            rows = cursor.fetchall()

            return [
                (
                    Email(row["email"]),
                    row["description"],
                    PublicKey(row["public_key"])
                )
                for row in rows
            ]
    
    # Returns information stored about an item. If this function panics, the
    # item doesn't exist. The result of this function contains the actual data
    # of the item, which may be megabytes long. To exclude the actual item data,
    # use `get_item_metadata`.
    def get_item(self, identifier: str) -> Item | None:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT auth_key, contents, release_keys, locks FROM items WHERE id = ?
                """,
                (identifier,),
            )
            value = cursor.fetchone()
            if value is None:
                return None
            
            return Item(
                auth_key=value["auth_key"],
                contents=value["contents"],
                release_keys=pickle.loads(str_to_bytes(value["release_keys"])),
                locks=value["locks"],
            )

    # Returns information stored about an item excluding the contents. If this
    # function panics, the item doesn't exist. "contents" are the actual data
    # of the item which may be megabytes long.
    def get_item_metadata(self, identifier: str) -> Item | None:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT auth_key, release_keys, locks FROM items WHERE id = ?
                """,
                (identifier,),
            )
            value = cursor.fetchone()
            if value is None:
                return None
            
            return Item(
                auth_key=value["auth_key"],
                contents="",
                release_keys=pickle.loads(str_to_bytes(value["release_keys"])),
                locks=value["locks"],
            )

    # Returns the authentication key of an item.
    def get_item_auth_key(self, identifier: str) -> str | None:
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                SELECT auth_key FROM items WHERE id = ?
                """,
                (identifier,),
            )
            value = cursor.fetchone()
            if value is None:
                raise Exception(f"item {identifier} doesn't exist")
            
            return value["auth_key"]

    # Removes the info about a user from the database. This function does not
    # panic if the user doesn't exist.
    def remove_user(self, email: Email):
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                DELETE FROM users WHERE email = ?
                """,
                (email.string,),
            )
            self._conn.commit()
    
    # Removes info about an item from the database. This function does not
    # panic if the item doesn't exist.
    def remove_item(self, identifier: str):
        with self._lock:
            cursor = self._conn.cursor()
            cursor.execute(
                """
                DELETE FROM items WHERE id = ?
                """,
                (identifier,),
            )
            self._conn.commit()
