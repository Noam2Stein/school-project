import re


class InvalidEmailError(Exception):
    """Raised when an email string is invalid."""
    pass


class Email:
    _EMAIL_REGEX = re.compile(
        r"^[a-zA-Z0-9_+\-]+@[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+$"
    )

    def __init__(self, string: str) -> None:
        if not isinstance(string, str):
            raise TypeError("Email must be initialized with a string")

        if not self._EMAIL_REGEX.match(string):
            raise InvalidEmailError(f"Invalid email: {string}")

        self.string: str = string

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Email):
            return False
        return self.string == other.string

    def __hash__(self) -> int:
        return hash(self.string)

    def __repr__(self) -> str:
        return f'Email("{self.string}")'
