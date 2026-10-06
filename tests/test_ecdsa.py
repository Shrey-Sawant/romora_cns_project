import pytest

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
