from uuid import UUID as Uuid
from datetime import datetime
from typing import Literal

class ClientBackend:
    def __init__(self):
        raise RuntimeError("todo")

    # fetch information from the server in the background. This needs to be called
    # when you want to refresh information. This is only `done` for a single call. After
    # the first `done` call, this function will try to fetch again.
    def fetch_from_server(self) -> Literal["wait", "not connected", "done", "unknown server error"]:
        raise RuntimeError("todo")

    # returns the global user list from the last fetch call. This returns immediatly
    # and performs nothing in the background.
    def global_user_emails(self) -> list[str] | Literal["havent fetched"]:
        raise RuntimeError("todo")

    # returns the description of a given user from the last fetch call. This returns
    # immediatly and doesnt do anything in the background.
    def global_user_description(self, email: str) -> str | Literal["havent fetched", "doesnt exist"]:
        raise RuntimeError("todo")

    # Logs in to an account in the background. This is considered `done` as long as
    # the client is logged in to the email passed to this function. This automatically syncs
    # or "fetches" with the server.
    def login(self, email: str, password: str) -> Literal["wait", "done", "not connected", "wrong password", "unknown server error"]:
        raise RuntimeError("todo")

    # Creates a new account in the background. This is considered done for a single call, before
    # trying again and failing with already exists. This automatically syncs or "fetches" with the server.
    def signup(self, email: str, password: str, description: str) -> Literal["wait", "done", "already exists", "invalid password", "not connected", "unknown server error"]:
        raise RuntimeError("todo")
    
    # Returns the email this client is currently logged in as. This is an error even if
    # the login is in progress right now.
    def logged_into_email(self) -> str | Literal["not logged in"]:
        raise RuntimeError("todo")

    # Returns a list of the items of the current account. This is not in the background.
    def my_item_ids(self) -> list[Uuid] | Literal["not logged in", "havent fetched"]:
        raise RuntimeError("todo")

    # Returns a list of items other users have invited this user to join. This
    # gives this user access to the item just like items of the user `my_item_ids` and
    # can be moved there using `join_item`. This is not in the background. The only
    # difference is that these items arent encrypted by this user.
    def my_item_invitation_ids(self) -> list[Uuid] | Literal["not logged in", "havent fetched"]:
        raise RuntimeError("todo")

    # Returns the name of an item. This should be a file name that also indicates the file type.
    # If a user wants the file type to be hidden they can always zip the item. This is not in the
    # background. This also works for items from `my_item_invitation_ids`.
    def item_name(self, id: Uuid) -> str | Literal["not logged in", "havent fetched", "doesnt exist"]:
        raise RuntimeError("todo")
        
    # Returns the display name of the item's encryption method. This is not in the
    # background. This also works for items from `my_item_invitation_ids`.
    def item_encryption_method(self, id: Uuid) -> str | Literal["not logged in", "havent fetched", "doesnt exist"]:
        raise RuntimeError("todo")

    # Returns the file size of an item. This is not in the
    # background. This also works for items from `my_item_invitation_ids`.
    def item_size(self, id: Uuid) -> int | Literal["not logged in", "havent fetched", "doesnt exist"]:
        raise RuntimeError("todo")

    # Checks if the item is locked, not including by ourselves from the last fetch.
    def item_is_locked(self, id: Uuid) -> bool | Literal["not logged in", "havent fetched", "doesnt exist", "corrupt"]:
        raise RuntimeError("todo")

    # Tries to fetch and decrypt the item in the background. The data only stays in
    # memory for a single call, after the first call returning bytes, it tries again from scratch.
    # This works whether or not this user has released their key.
    def read_item(self, id: Uuid) -> bytes | Literal["wait", "not connected", "not logged in", "havent fetched", "doesnt exist", "locked", "corrupt", "unknown server error"]:
        raise RuntimeError("todo")

    # Gives a release key to the server in the background. Its the server's job to delete
    # the key after `until`.
    def release_item(self, id: Uuid, until: datetime) -> Literal["wait", "done", "not logged in", "havent fetched", "doesnt exist", "corrupt", "havent joined", "unknown server error"]:
        raise RuntimeError("todo")

    # Moves an item from the list of items we got an invitation to, to being one of our items.
    # The only behavioural change this has is that it encrypts the item by this user.
    def join_item(self, id: Uuid) -> Literal["wait", "done", "not logged in", "havent fetched", "doesnt exist", "corrupt", "unknown server error"]:
        raise RuntimeError("todo")
    
    # Removes an item from the invitation list in the background.
    def reject_item(self, id: Uuid) -> Literal["wait", "done", "not logged in", "havent fetched", "doesnt exist", "corrupt", "unknown server error"]:
        raise RuntimeError("todo")

    # Returns true if based on the last fetch this user released their key.
    def has_released_item(self, id: Uuid) -> bool | Literal["not logged in", "havent fetched", "doesnt exist", "corrupt"]:
        raise RuntimeError("todo")

    # Based on the last fetch returns the time limit of the user's release key, only if they have one.
    def released_item_timelimit(self, id: Uuid) -> datetime | Literal["not logged in", "havent fetched", "doesnt exist", "corrupt", "havent released"]:
        raise RuntimeError("todo")

    # Creates a new item in the background. This is considered done only for a single call,
    # after the first call, itll try to create another item with the same name.
    def create_item(self, name: str, data: bytes) -> Literal["wait", "done", "not logged in", "corrupt", "not connected", "unknown server error"]:
        raise RuntimeError("todo")
    
    # Invites another user to the given item in the background. This gives that
    # user full permissions to delete or encrypt the item.
    def invite_user_to_item(self, user_email: str, item_id: Uuid) -> Literal["wait", "done", "not logged in", "corrupt", "not connected", "item doesnt exist", "user doesnt exist", "unknown server error"]:
        raise RuntimeError("todo")

    # Deletes an item for everybody involved in the background.
    def delete_item(self, id: Uuid) -> Literal["wait", "done", "not logged in", "doesnt exist", "corrupt", "not connected", "unknown server error"]:
        raise RuntimeError("todo")

    # Leaves an item releasing our key forever in the background.
    def leave_and_release_item(self, id: Uuid) -> Literal["wait", "done", "not logged in", "doesnt exist", "corrupt", "not connected", "unknown server error"]:
        raise RuntimeError("todo")
