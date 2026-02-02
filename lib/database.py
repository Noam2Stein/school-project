import sqlite3
import pickle
from dataclasses import dataclass
from datetime import datetime
from threading import Lock
from uuid import UUID as Uuid

from lib.key import Key
from lib.email import Email

@dataclass
class User:
    auth_key: Key
    items: bytes
    public_key: Key
    messages: list[bytes]
    description: str

@dataclass
class ReleaseKey:
    key: bytes
    expires: datetime

@dataclass
class Item:
    auth_key: Key
    contents: bytes
    release_keys: list[ReleaseKey]

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
                    items BLOB,
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
                INSERT OR REPLACE INTO users (email, auth_key, items, public_key, messages) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    email.string,
                    value.auth_key.value.to_bytes(32),
                    value.items,
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
    
    def get_user(self, email: Email) -> User:
        with self._lock:
            self._cursor.execute(
                """
                SELECT auth_key, items, public_key, messages FROM users WHERE email = ?
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
                items=value["items"],
                public_key=Key(int.from_bytes(value["public_key"])),
                messages=pickle.loads(value["messages"]),
                description=description_value["description"],
            )
        
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

    def remove_user(self, email: Email):
        with self._lock:
            self._cursor.execute(
                """
                DELETE FROM users WHERE email = ?
                """,
                (email.string,),
            )
            self._conn.commit()
    
    def remove_item(self, id: Uuid):
        with self._lock:
            self._cursor.execute(
                """
                DELETE FROM items WHERE id = ?
                """,
                (id.bytes,),
            )
            self._conn.commit()
