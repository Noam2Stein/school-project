import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def encrypt(data: bytes, pub_key) -> bytes:
    aes_key = os.urandom(32)
    aes = AESGCM(aes_key)

    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, data, None)

    encrypted_key = pub_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return encrypted_key + nonce + ciphertext

def decrypt(blob: bytes, priv_key) -> bytes:
    encrypted_key = blob[:256]
    nonce = blob[256:268]
    ciphertext = blob[268:]

    aes_key = priv_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    aes = AESGCM(aes_key)
    return aes.decrypt(nonce, ciphertext, None)
