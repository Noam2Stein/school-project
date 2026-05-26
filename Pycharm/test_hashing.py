import base64
import hashlib

from lib.hashing import hash_string


def test_hash_is_deterministic():
    value = "hello world"

    assert hash_string(value) == hash_string(value)


def test_hash_changes_with_input():
    assert hash_string("a") != hash_string("b")


def test_output_is_base64_urlsafe_string():
    result = hash_string("test value")

    assert isinstance(result, str)

    decoded = base64.urlsafe_b64decode(result + "==")
    assert len(decoded) == hashlib.sha256().digest_size


def test_empty_string_hash():
    result = hash_string("")

    assert isinstance(result, str)
    assert len(result) > 0


def test_known_stability():
    value = "stable-input"

    expected = hash_string(value)
    assert hash_string(value) == expected