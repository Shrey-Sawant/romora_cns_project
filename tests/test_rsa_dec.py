import pytest

from crypto.rsa_dec import decrypt
from crypto.rsa_enc import encrypt, generate_keypair


def test_rsa_round_trip_string():
    priv, pub = generate_keypair()
    original_message = "Meet me at 5:30 PM behind the observatory."

    ciphertext = encrypt(pub, original_message)
    assert len(ciphertext) == 256

    decrypted = decrypt(priv, ciphertext)
    assert decrypted == original_message


def test_rsa_round_trip_exact_190_bytes():
    priv, pub = generate_keypair()
    # 190 bytes exact
    max_message = "A" * 190

    ciphertext = encrypt(pub, max_message)
    decrypted = decrypt(priv, ciphertext)
    assert decrypted == max_message


def test_rsa_round_trip_unicode():
    priv, pub = generate_keypair()
    message = "Secret 🔐 秘密 🛡️"

    ciphertext = encrypt(pub, message)
    decrypted = decrypt(priv, ciphertext)
    assert decrypted == message


def test_rsa_decrypt_with_wrong_key_fails():
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()

    ciphertext = encrypt(pub_a, "Top secret for Alice only")

    # Bob attempts to decrypt Alice's ciphertext
    with pytest.raises(ValueError, match="RSA decryption failed: invalid ciphertext or wrong key"):
        decrypt(priv_b, ciphertext)


def test_rsa_decrypt_tampered_ciphertext_fails():
    priv, pub = generate_keypair()
    ciphertext = bytearray(encrypt(pub, "Classified message"))

    # Tamper with 1 byte in the ciphertext
    ciphertext[50] ^= 0xFF

    with pytest.raises(ValueError, match="RSA decryption failed: invalid ciphertext or wrong key"):
        decrypt(priv, bytes(ciphertext))


def test_rsa_decrypt_invalid_length_fails():
    priv, pub = generate_keypair()

    with pytest.raises(ValueError, match="Invalid ciphertext length"):
        decrypt(priv, b"too_short")
