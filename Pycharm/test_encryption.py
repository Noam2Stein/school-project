import pytest

from lib.encryption import keypair, encrypt, decrypt


def test_encrypt_decrypt_roundtrip():
    private_key, public_key = keypair("correct horse battery staple")

    message = b"hello world"
    encrypted = encrypt(public_key, message)
    decrypted = decrypt(private_key, encrypted)

    assert decrypted == message


def test_different_messages_produce_different_ciphertext():
    private_key, public_key = keypair("password")

    msg1 = b"message one"
    msg2 = b"message two"

    enc1 = encrypt(public_key, msg1)
    enc2 = encrypt(public_key, msg2)

    assert enc1 != enc2


def test_same_password_produces_same_keypair():
    private1, pub1 = keypair("same password")
    private2, pub2 = keypair("same password")

    assert private1 == private2
    assert pub1 == pub2


def test_different_password_produces_different_keypair():
    private1, pub1 = keypair("password one")
    private2, pub2 = keypair("password two")

    assert private1 != private2
    assert pub1 != pub2


def test_tampered_ciphertext_fails():
    private_key, public_key = keypair("secure password")

    message = b"secret"
    encrypted = bytearray(encrypt(public_key, message))

    encrypted[-1] ^= 1  # flip a bit

    with pytest.raises(Exception):
        decrypt(private_key, bytes(encrypted))


test_encrypt_decrypt_roundtrip()
test_different_messages_produce_different_ciphertext()
test_same_password_produces_same_keypair()
test_different_password_produces_different_keypair()
test_tampered_ciphertext_fails()
