import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from crypto.ecdsa import (
    deserialize_private_key,
    deserialize_public_key,
    generate_keypair,
    public_key_fingerprint,
    serialize_private_key,
    serialize_public_key,
    sign,
    verify,
)


def test_generate_keypair_returns_p256_keys():
    private_key, public_key = generate_keypair()

    assert private_key.curve.name == "secp256r1"
    assert public_key.curve.name == "secp256r1"


def test_sign_and_verify_round_trip():
    private_key, public_key = generate_keypair()
    message = "sender → receiver: secret message"

    signature = sign(private_key, message)

    assert len(signature) == 64
    assert verify(public_key, message, signature) is True


def test_verify_rejects_tampered_message():
    private_key, public_key = generate_keypair()
    signature = sign(private_key, "original message")

    assert verify(public_key, "tampered message", signature) is False


def test_verify_rejects_wrong_public_key():
    private_key_a, public_key_a = generate_keypair()
    _, public_key_b = generate_keypair()
    signature = sign(private_key_a, "top secret")

    assert verify(public_key_b, "top secret", signature) is False


def test_public_key_serialization_round_trip():
    _, public_key = generate_keypair()

    encoded = serialize_public_key(public_key)
    restored = deserialize_public_key(encoded)
    assert restored.public_numbers() == public_key.public_numbers()

    fingerprint = public_key_fingerprint(public_key, as_hex=True)
    assert isinstance(fingerprint, str)
    assert len(fingerprint) == 64


def test_private_key_serialization_round_trip():
    private_key, _ = generate_keypair()

    encoded = serialize_private_key(private_key)
    restored = deserialize_private_key(encoded)
    assert restored.private_numbers() == private_key.private_numbers()


def test_sign_and_verify_exact_bytes():
    private_key, public_key = generate_keypair()
    raw_payload = b"\x00\xff\xaa\x55binary\x00data\x01\x02\x03"

    signature = sign(private_key, raw_payload)
    assert len(signature) == 64
    assert verify(public_key, raw_payload, signature) is True

    # Modified bytes must not verify
    tampered_payload = b"\x00\xff\xaa\x55binary\x00data\x01\x02\x04"
    assert verify(public_key, tampered_payload, signature) is False


def test_verify_rejects_malformed_and_invalid_signatures():
    private_key, public_key = generate_keypair()
    valid_sig = sign(private_key, b"target message")

    # Wrong length
    assert verify(public_key, b"target message", b"too_short") is False
    assert verify(public_key, b"target message", valid_sig[:63]) is False
    assert verify(public_key, b"target message", valid_sig + b"\x00") is False

    # Zero signature (r=0, s=0 are invalid DSA components)
    assert verify(public_key, b"target message", b"\x00" * 64) is False

    # Tampered signature byte
    mutated_sig = bytearray(valid_sig)
    mutated_sig[10] ^= 0x01
    assert verify(public_key, b"target message", bytes(mutated_sig)) is False

    # Non-bytes signature inputs fail safely as False
    assert verify(public_key, b"target message", "string_signature") is False
    assert verify(public_key, b"target message", None) is False
    assert verify(public_key, b"target message", 12345) is False


def test_ecdsa_deserialize_rejects_malformed_truncated_and_unsupported():
    with pytest.raises(ValueError):
        deserialize_public_key(b"not a valid pem")

    truncated_pem = b"-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE"
    with pytest.raises(ValueError):
        deserialize_public_key(truncated_pem)

    foreign_priv = ec.generate_private_key(ec.SECP384R1())
    foreign_pub_pem = foreign_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(ValueError, match="Expected secp256r1 curve, got secp384r1"):
        deserialize_public_key(foreign_pub_pem)

    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub_pem = rsa_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(TypeError, match="The provided key is not an EC public key."):
        deserialize_public_key(rsa_pub_pem)

    with pytest.raises(TypeError, match="Public key data must be bytes-like."):
        deserialize_public_key("not-bytes-string")

    with pytest.raises(ValueError):
        deserialize_private_key(b"not a valid pem")

    foreign_priv_pem = foreign_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(ValueError, match="Expected secp256r1 curve, got secp384r1"):
        deserialize_private_key(foreign_priv_pem)

    rsa_priv_pem = rsa_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(TypeError, match="The provided key is not an EC private key."):
        deserialize_private_key(rsa_priv_pem)

    with pytest.raises(TypeError, match="Private key data must be bytes-like."):
        deserialize_private_key("not-bytes-string")
