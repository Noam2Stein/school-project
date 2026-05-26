from __future__ import annotations

import hashlib
import os
from typing import NewType

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from lib.encode_default import bytes_to_str, str_to_bytes

PublicKey = NewType("PublicKey", str)
PrivateKey = NewType("PrivateKey", str)

_KEY_BYTES = 32
_NONCE_BYTES = 12
_MAGIC = b"CBX1"

_KEY_DERIVATION_CONTEXT = b"cbx1-encryption"


def keypair(password: str, salt: bytes = b"i-hate-school") -> tuple[PrivateKey, PublicKey]:
    seed = hashlib.scrypt(
        password=password.encode("utf-8"),
        salt=salt,
        n=2**13,
        r=8,
        p=1,
        dklen=_KEY_BYTES,
    )

    private_key = X25519PrivateKey.from_private_bytes(seed)
    public_key = private_key.public_key()

    return (
        PrivateKey(bytes_to_str(private_key.private_bytes_raw())),
        PublicKey(bytes_to_str(public_key.public_bytes_raw())),
    )


def _load_private_key(key: PrivateKey) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(str_to_bytes(str(key)))


def _load_public_key(key: PublicKey) -> X25519PublicKey:
    return X25519PublicKey.from_public_bytes(str_to_bytes(str(key)))


def _derive_encryption_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=_KEY_BYTES,
        salt=None,
        info=_KEY_DERIVATION_CONTEXT,
    ).derive(shared_secret)


def encrypt(key: PublicKey, data: bytes) -> bytes:
    recipient_public_key = _load_public_key(key)

    ephemeral_private_key = X25519PrivateKey.generate()
    ephemeral_public_key = ephemeral_private_key.public_key()

    shared_secret = ephemeral_private_key.exchange(recipient_public_key)

    encryption_key = _derive_encryption_key(shared_secret)

    nonce = os.urandom(_NONCE_BYTES)

    ciphertext = ChaCha20Poly1305(encryption_key).encrypt(
        nonce,
        data,
        None,
    )

    return (
        _MAGIC
        + ephemeral_public_key.public_bytes_raw()
        + nonce
        + ciphertext
    )


def decrypt(key: PrivateKey, data: bytes) -> bytes:
    if data[:4] != _MAGIC:
        raise ValueError("invalid ciphertext format")

    offset = 4

    ephemeral_public_key_bytes = data[offset:offset + _KEY_BYTES]
    offset += _KEY_BYTES

    nonce = data[offset:offset + _NONCE_BYTES]
    offset += _NONCE_BYTES

    ciphertext = data[offset:]

    recipient_private_key = _load_private_key(key)

    ephemeral_public_key = X25519PublicKey.from_public_bytes(ephemeral_public_key_bytes)

    shared_secret = recipient_private_key.exchange(ephemeral_public_key)

    encryption_key = _derive_encryption_key(shared_secret)

    return ChaCha20Poly1305(encryption_key).decrypt(
        nonce,
        ciphertext,
        None,
    )
