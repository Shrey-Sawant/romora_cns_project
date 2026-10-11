import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from crypto import rsa_enc


@pytest.fixture(scope="module")
def keys():
    return rsa_enc.generate_keypair()


def test_keypair_is_rsa_2048_e65537(keys):
    private_key, public_key = keys
    assert public_key.key_size == 2048
    assert public_key.public_numbers().e == 65537


def test_ciphertext_is_256_bytes_and_decrypts(keys):
    private_key, public_key = keys
    ct = rsa_enc.encrypt(public_key, "hello")
    assert len(ct) == 256
    assert private_key.decrypt(ct, rsa_enc.oaep_padding()) == b"hello"


def test_oaep_is_randomized(keys):
    _, public_key = keys
    assert rsa_enc.encrypt(public_key, "same") != rsa_enc.encrypt(public_key, "same")


def test_exactly_190_bytes_works(keys):
    private_key, public_key = keys
    msg = b"a" * 190
    assert private_key.decrypt(rsa_enc.encrypt(public_key, msg), rsa_enc.oaep_padding()) == msg


def test_191_bytes_rejected(keys):
    with pytest.raises(ValueError, match="too long"):
        rsa_enc.encrypt(keys[1], b"a" * 191)


def test_limit_counts_utf8_bytes_not_characters(keys):
    with pytest.raises(ValueError):
        rsa_enc.encrypt(keys[1], "é" * 100)  # 200 bytes


def test_unicode_round_trip(keys):
    private_key, public_key = keys
    msg = "नमस्ते 🔐"
    ct = rsa_enc.encrypt(public_key, msg)
    assert private_key.decrypt(ct, rsa_enc.oaep_padding()).decode("utf-8") == msg


def test_empty_message_rejected(keys):
    with pytest.raises(ValueError):
        rsa_enc.encrypt(keys[1], "")


def test_bad_types_rejected(keys):
    with pytest.raises(TypeError):
        rsa_enc.encrypt(keys[1], 123)
    with pytest.raises(TypeError):
        rsa_enc.encrypt("not a key", "hi")


def test_wrong_key_size_rejected():
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024).public_key()
    with pytest.raises(ValueError):
        rsa_enc.encrypt(small, "hi")


def test_pem_round_trip_and_fingerprint(keys):
    private_key, public_key = keys
    pub2 = rsa_enc.deserialize_public_key(rsa_enc.serialize_public_key(public_key))
    priv2 = rsa_enc.deserialize_private_key(rsa_enc.serialize_private_key(private_key))
    assert rsa_enc.public_key_fingerprint(pub2) == rsa_enc.public_key_fingerprint(public_key)
    assert len(rsa_enc.public_key_fingerprint(public_key)) == 64
    assert priv2.decrypt(rsa_enc.encrypt(pub2, "x"), rsa_enc.oaep_padding()) == b"x"
