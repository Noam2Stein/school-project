import argon2

class Key:
    """
    A 256-bit key stored as an unsigned integer.
    """

    def __init__(self, value: int):
        if value < 0:
            raise RuntimeError("`Key` cannot be negative")
        
        if value >= 2**256:
            raise RuntimeError("`Key` must fit in an unsigned 256-bit integer")
        
        self.value = value

    def __eq__(self, other):
        return self.value == other.value

    def __repr__(self):
        return f"Key({self.value})"
    
    def hash(self) -> 'Key':
        key_bytes = self.value.to_bytes(32)
        hash_bytes = argon2.low_level.hash_secret_raw(
            secret=key_bytes,
            salt=b"yarden-cohen",
            time_cost=3,
            memory_cost=102400,
            parallelism=4,
            hash_len=32,
            type=argon2.low_level.Type.ID,
        )

        return Key(int.from_bytes(hash_bytes))
