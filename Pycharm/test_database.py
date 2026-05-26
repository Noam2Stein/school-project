import shutil
from pathlib import Path
from uuid import uuid4
from tempfile import mkdtemp
from datetime import datetime

from lib.database import Database, User, Item, ReleaseKey
from lib.email import Email
from lib.encryption import PublicKey


# ------------------------
# assertions
# ------------------------
def assert_eq(a, b):
    if a != b:
        raise RuntimeError(f"{a} != {b}")


def assert_(cond):
    if not cond:
        raise RuntimeError("assertion failed")


def assert_panic(fn):
    try:
        fn()
    except Exception:
        return
    raise RuntimeError("expected exception")


# ------------------------
# create isolated DB
# ------------------------
DATA_DIR = Path(mkdtemp())
db = Database(str(DATA_DIR))


# =========================
# EMPTY DB TEST
# =========================
missing_email = Email("missing@example.com")
missing_item = str(uuid4())

assert_(not db.has_user(missing_email))
assert_eq(db.get_user(missing_email), None)
assert_eq(db.get_user_auth_key(missing_email), None)

assert_(not db.has_item(missing_item))
assert_eq(db.get_item(missing_item), None)
assert_eq(db.get_item_metadata(missing_item), None)
assert_panic(lambda: db.get_item_auth_key(missing_item))

assert_eq(db.get_user_emails_descs_pub_keys(), [])


# =========================
# USERS
# =========================
email1 = Email("a@a.com")
email2 = Email("b@b.com")

user1 = User(
    auth_key="k1",
    private_info="x",
    public_key=PublicKey("p1"),
    messages=["m1"],
    description="u1",
)

user2 = User(
    auth_key="k2",
    private_info="y",
    public_key=PublicKey("p2"),
    messages=["m2"],
    description="u2",
)

# insert user1
db.insert_user(email1, user1, False)

assert_(db.has_user(email1))
assert_eq(db.get_user(email1), user1)

assert_eq(
    db.get_user_emails_descs_pub_keys(),
    [(email1, user1.description, user1.public_key)]
)

# duplicate insert should fail
assert_panic(lambda: db.insert_user(email1, user1, False))

# update user1
db.insert_user(email1, user2, True)
assert_eq(db.get_user(email1), user2)

# insert user2
db.insert_user(email2, user1, False)
assert_(db.has_user(email2))


# =========================
# ITEMS
# =========================
item_id = str(uuid4())

r1 = ReleaseKey("r1", datetime.now())

item1 = Item("a1", "c1", [r1])
item2 = Item("a2", "c2", [r1])

# insert
db.insert_item(item_id, item1, False)

assert_(db.has_item(item_id))
assert_eq(db.get_item(item_id), item1)

# metadata
meta = db.get_item_metadata(item_id)
assert_eq(meta.contents, "")

# duplicate insert should fail
assert_panic(lambda: db.insert_item(item_id, item1, False))

# update
db.insert_item(item_id, item2, True)
assert_eq(db.get_item(item_id), item2)


# =========================
# REMOVE
# =========================
db.remove_user(email1)
assert_(not db.has_user(email1))

db.remove_item(item_id)
assert_(not db.has_item(item_id))


# =========================
# CLEANUP (IMPORTANT FIX)
# =========================
# close DB BEFORE deleting folder (prevents Windows lock)
try:
    db._conn.close()
except:
    pass

shutil.rmtree(DATA_DIR, ignore_errors=True)

print("ALL TESTS PASSED")
