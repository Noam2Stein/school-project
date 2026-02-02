import shutil
import os
from pathlib import Path
from uuid import uuid4
from datetime import datetime

from lib.database import Database, User, Item, ReleaseKey
from lib.email import Email
from lib.key import Key

def assert_panic(f):
    try:
        f()
    except:
        return
    raise RuntimeError("Function did not panic")

def assert_eq(a, b):
    if a != b:
        raise RuntimeError(f"{a} != {b}")

SCRIPT_DIR = Path(__file__).resolve().parent
DATA_DIR = f"{SCRIPT_DIR}/__data__"

shutil.rmtree(DATA_DIR)
os.mkdir(DATA_DIR)
db = Database(DATA_DIR)

user_email1 = Email("yarden@cohen.com")
user_email2 = Email("yarden@kohen.com")

user1 = User(
    auth_key=Key(47584093698567567586),
    items=b"riorjgiognert9y45y6897457ytgmc0456yt45",
    public_key=Key(3457890345780347089465),
    messages=[b"gerijgterio", b"helloworld"],
    description="The first user used for the test",
)
user2 = User(
    auth_key=Key(7568904508934560893456),
    items=b"rtnu7g6y456764bvo675y0e640",
    public_key=Key(34507894563787045670893456),
    messages=[b"eryuiodffgnjkldcvn", b"ghghghghgh"],
    description="The second user used for the test",
)

item_id1 = uuid4()
item_id2 = uuid4()

item1 = Item(
    auth_key=Key(120486734908862309468730984),
    contents=b"esrguhjolesryhiioluhsresiolyeyrsesrytuiolioleyurioluesyrtesrtui",
    release_keys=[ReleaseKey(
        key=b"esyrgiouhio3uhio4hafsiouhi456wuhszdhfgiouhw45tiosdfgesrtg",
        expires=datetime.now(),
    )],
)
item2 = Item(
    auth_key=Key(34278934567890456709834567),
    contents=b"eiorguiluhj34567hjiouhsgdiuh3456iouhrtgesesrg",
    release_keys=[ReleaseKey(
        key=b"sdfghioj45e6yiojpesrge45yjiorsdtheshrtge45yioey45rij4we5iohjesriot",
        expires=datetime.now(),
    )],
)

release_key_id1 = uuid4()
release_key_id2 = uuid4()

db.insert_user(user_email1, user1, False)
assert_panic(lambda: db.insert_user(user_email1, user1, False))
db.insert_user(user_email1, user1, True)
assert_eq(db.get_user(user_email1), user1)
db.insert_user(user_email1, user2, True)
assert_eq(db.get_user(user_email1), user2)

db.insert_user(user_email2, user1, False)
assert_panic(lambda: db.insert_user(user_email2, user1, False))
db.insert_user(user_email2, user1, True)
assert_eq(db.get_user(user_email2), user1)
db.insert_user(user_email2, user2, True)
assert_eq(db.get_user(user_email2), user2)

db.insert_item(item_id1, item1, False)
assert_panic(lambda: db.insert_item(item_id1, item1, False))
db.insert_item(item_id1, item1, True)
assert_eq(db.get_item(item_id1), item1)
db.insert_item(item_id1, item2, True)
assert_eq(db.get_item(item_id1), item2)

db.insert_item(item_id2, item1, False)
assert_panic(lambda: db.insert_item(item_id2, item1, False))
db.insert_item(item_id2, item1, True)
assert_eq(db.get_item(item_id2), item1)
db.insert_item(item_id2, item2, True)
assert_eq(db.get_item(item_id2), item2)
