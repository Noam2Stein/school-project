import pytest
from lib.email import Email, InvalidEmailError


@pytest.mark.parametrize("email_str", [
    "test@example.com",
    "john_doe+tag@domain.co",
    "a1_b2-c3@site-123.org",
])
def test_valid_emails(email_str: str) -> None:
    assert Email(email_str).string == email_str


@pytest.mark.parametrize("email_str", [
    "plain_address",
    "@missing_local.com",
    "missing_at.com",
    "name@",
    "name@domain",
    "name@domain..com",
    "name@domain.c om",
    "name@domain@domain.com",
    "name@.com",
    "name@domain.",
    "name domain@example.com",
    "name@domain_com",
])
def test_invalid_emails(email_str: str) -> None:
    with pytest.raises(InvalidEmailError):
        Email(email_str)


def test_email_equality() -> None:
    assert Email("test@example.com") == Email("test@example.com")
    assert Email("a@example.com") != Email("b@example.com")


def test_email_vs_non_email() -> None:
    assert Email("test@example.com") != "test@example.com"


def test_email_repr() -> None:
    assert repr(Email("test@example.com")) == 'Email("test@example.com")'
