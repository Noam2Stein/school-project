import pytest

from lib.encode_default import bytes_to_str, str_to_bytes


# -----------------------
# round-trip tests
# -----------------------

@pytest.mark.parametrize("data", [
    b"",
    b"hello",
    b"world",
    b"\x00\x01\x02",
    b"binary\xffdata",
    b"longer text with spaces and symbols !@#$%^&*()",
])
def test_b64_round_trip(data: bytes) -> None:
    encoded = bytes_to_str(data)
    decoded = str_to_bytes(encoded)

    assert isinstance(encoded, str)
    assert isinstance(decoded, bytes)
    assert decoded == data


# -----------------------
# known values test
# -----------------------

def test_b64_known_value() -> None:
    assert bytes_to_str(b"hello") == "aGVsbG8="
    assert str_to_bytes("aGVsbG8=") == b"hello"


# -----------------------
# empty input
# -----------------------

def test_b64_empty() -> None:
    assert bytes_to_str(b"") == ""
    assert str_to_bytes("") == b""
