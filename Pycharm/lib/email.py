import re

class Email:
    _EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+$")

    def __init__(self, string: str):
        if not self._EMAIL_REGEX.match(string):
            raise RuntimeError(f"Invalid email: {string}")
        
        self._string = string

    def __eq__(self, other):
        return self._string == other._string
    
    def __repr__(self):
        return f"Email(\"{self._string}\")"

    @property
    def string(self) -> str:
        return self._string
