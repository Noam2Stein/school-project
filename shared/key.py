import argon2

class KeyHash:
    """
    A 256-bit hash of a `Key` stored as an unsigned integer.
    """

    def __init__(self, value: int):
        if value < 0:
            raise RuntimeError("`KeyHash` cannot be negative")
        
        if value >= 2**256:
            raise RuntimeError("`KeyHash` must fit in an unsigned 256-bit integer")
        
        self._value = value

    def __eq__(self, other):
        return self._value == other._value

    def value(self) -> int:
        return self._value

class Key:
    """
    A 256-bit key stored as an unsigned integer.
    """

    def __init__(self, value: int):
        if value < 0:
            raise RuntimeError("`Key` cannot be negative")
        
        if value >= 2**256:
            raise RuntimeError("`Key` must fit in an unsigned 256-bit integer")
        
        self._value = value

    def value(self) -> int:
        return self._value
    
    def hash(self) -> KeyHash:
        key_bytes = self.value().to_bytes(32)
        hash_bytes = argon2.low_level.hash_secret_raw(
            secret=key_bytes,
            salt=b"yarden-cohen",
            time_cost=3,
            memory_cost=102400,
            parallelism=4,
            hash_len=32,
            type=argon2.low_level.Type.ID,
        )

        return KeyHash(int.from_bytes(hash_bytes))
