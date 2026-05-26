import json
from dataclasses import asdict, is_dataclass

from lib.request_response import (
    SignupRequest,
    SignupResponse,
    LoginRequest,
    LoginResponse,
    FetchRequest,
    FetchResponse,
    PushRequest,
    PushResponse,
    SendRequest,
    SendResponse,
    ItemRequest,
    ItemResponse,
    CreateItemRequest,
    CreateItemResponse,
    EncryptItemRequest,
    EncryptItemResponse,
    ReleaseItemRequest,
    ReleaseItemResponse,
    PublicKey,
)


# -----------------------------
# JSON helpers
# -----------------------------

def to_json(obj) -> str:
    return json.dumps(asdict(obj))


def from_json(cls, data: str):
    return cls(**json.loads(data))


# -----------------------------
# Fixtures
# -----------------------------

def sample_key() -> PublicKey:
    return PublicKey("deadbeef-public-key")


# -----------------------------
# Generic round-trip tester
# -----------------------------

def roundtrip(obj, cls):
    assert is_dataclass(obj)

    encoded = to_json(obj)
    decoded = from_json(cls, encoded)

    assert isinstance(encoded, str)
    assert isinstance(decoded, cls)
    assert decoded == obj


# -----------------------------
# Tests: Requests
# -----------------------------

def test_signup_request_json():
    roundtrip(
        SignupRequest(
            email="a@b.com",
            auth_key="auth",
            private_info="encrypted",
            public_key=sample_key(),
        ),
        SignupRequest,
    )


def test_login_request_json():
    roundtrip(
        LoginRequest(email="a@b.com", auth_key="auth"),
        LoginRequest,
    )


def test_fetch_request_json():
    roundtrip(FetchRequest(), FetchRequest)


def test_push_request_json():
    roundtrip(
        PushRequest(
            private_info="enc",
            messages=["m1", "m2"],
        ),
        PushRequest,
    )


def test_send_request_json():
    roundtrip(
        SendRequest(
            target_email="x@y.com",
            content="encrypted-msg",
        ),
        SendRequest,
    )


def test_item_request_json():
    roundtrip(
        ItemRequest(
            id="item123",
            auth_key="auth",
        ),
        ItemRequest,
    )


def test_create_item_request_json():
    roundtrip(
        CreateItemRequest(
            contents="encrypted",
            auth_key="auth",
        ),
        CreateItemRequest,
    )


def test_encrypt_item_request_json():
    roundtrip(
        EncryptItemRequest(
            id="item123",
            auth_key="auth",
            public_key=PublicKey("pubkey"),
            prefix="prefix",
        ),
        EncryptItemRequest,
    )


def test_release_item_request_json():
    roundtrip(
        ReleaseItemRequest(
            id="item123",
            auth_key="auth",
            info="release-info",
            expires="2026-01-01T00:00:00Z",
        ),
        ReleaseItemRequest,
    )


# -----------------------------
# Tests: Responses
# -----------------------------

def test_signup_response_json():
    roundtrip(
        SignupResponse(is_success=True, email_is_taken=False),
        SignupResponse,
    )


def test_login_response_json():
    roundtrip(
        LoginResponse(
            is_success=True,
            incorrect_password=False,
            user_doesnt_exist=False,
        ),
        LoginResponse,
    )


def test_fetch_response_json():
    roundtrip(
        FetchResponse(
            is_success=True,
            not_logged_in=False,
            private_info="enc",
            messages=["m1"],
            user_emails=["a@b.com"],
            user_descriptions=["desc"],
            user_public_keys=[sample_key()],
        ),
        FetchResponse,
    )


def test_push_response_json():
    roundtrip(
        PushResponse(
            is_success=True,
            not_logged_in=False,
        ),
        PushResponse,
    )


def test_send_response_json():
    roundtrip(
        SendResponse(
            is_success=True,
            invalid_email=False,
            user_doesnt_exist=False,
            not_logged_in=False,
        ),
        SendResponse,
    )


def test_item_response_json():
    roundtrip(
        ItemResponse(
            is_success=True,
            wrong_key=False,
            contents="enc",
            release_key_contents=["rk1"],
        ),
        ItemResponse,
    )


def test_create_item_response_json():
    roundtrip(
        CreateItemResponse(
            is_success=True,
            id="item123",
        ),
        CreateItemResponse,
    )


def test_encrypt_item_response_json():
    roundtrip(
        EncryptItemResponse(
            is_success=True,
            wrong_key=False,
        ),
        EncryptItemResponse,
    )


def test_release_item_response_json():
    roundtrip(
        ReleaseItemResponse(
            is_success=True,
            wrong_key=False,
        ),
        ReleaseItemResponse,
    )
