import hashlib


class InvalidKeyError(Exception):
    pass


class Key:
    """
    A 256-bit key stored as an unsigned integer.
    """

    def __init__(self, value: int):
        if value < 0:
            raise InvalidKeyError("`Key` cannot be negative")

        if value >= 2 ** 256:
            raise InvalidKeyError("`Key` must fit in an unsigned 256-bit integer")

        self.value = value

    def __eq__(self, other):
        return self.value == other.value

    def __repr__(self):
        return f"Key({self.value})"

    def hash(self) -> 'Key':
        key_bytes = self.value.to_bytes(32)
        hash_bytes = hashlib.scrypt(
            password=key_bytes,
            salt=b"yarden-cohen",
            # `n` is internal memory size. (python has no docs...).
            n=2 ** 14,
            r=8,
            p=1,
            # output byte count. (python has no docs...).
            dklen=32,
        )

        return Key(int.from_bytes(hash_bytes))