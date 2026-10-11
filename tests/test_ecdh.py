import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from crypto.ecdh import (
    compute_shared_secret,
    derive_session,
    derive_session_id,
    derive_session_key,
    deserialize_private_key,
    deserialize_public_key,
    generate_keypair,
    public_key_fingerprint,
    serialize_private_key,
    serialize_public_key,
    validate_and_complete_handshake,
)
from crypto.ecdsa import (
    generate_keypair as generate_identity_keypair,
    sign as ecdsa_sign,
)


def test_generate_ecdh_keypair_returns_p256():
    priv, pub = generate_keypair()
    assert priv.curve.name == "secp256r1"
    assert pub.curve.name == "secp256r1"


def test_ecdh_serialization_round_trip():
    priv, pub = generate_keypair()

    pub_bytes = serialize_public_key(pub)
    restored_pub = deserialize_public_key(pub_bytes)
    assert restored_pub.public_numbers() == pub.public_numbers()

    priv_bytes = serialize_private_key(priv)
    restored_priv = deserialize_private_key(priv_bytes)
    assert restored_priv.private_numbers() == priv.private_numbers()

    fingerprint = public_key_fingerprint(pub, as_hex=True)
    assert isinstance(fingerprint, str)
    assert len(fingerprint) == 64


def test_both_parties_derive_identical_session():
    # Alice (Sender)
    alice_priv, alice_pub = generate_keypair()
    # Bob (Receiver - Nirupam's role)
    bob_priv, bob_pub = generate_keypair()

    alice_key, alice_sid = derive_session(alice_priv, bob_pub)
    bob_key, bob_sid = derive_session(bob_priv, alice_pub)

    assert len(alice_key) == 32
    assert len(alice_sid) == 32
    assert alice_key == bob_key
    assert alice_sid == bob_sid
    # Session ID must be distinct from session key
    assert alice_key != alice_sid


def test_validate_and_complete_handshake_success():
    # Long-term identities
    alice_id_priv, alice_id_pub = generate_identity_keypair()
    bob_id_priv, bob_id_pub = generate_identity_keypair()

    # Ephemeral ECDH keys
    alice_ecdh_priv, alice_ecdh_pub = generate_keypair()
    bob_ecdh_priv, bob_ecdh_pub = generate_keypair()

    # Alice signs her ephemeral ECDH public key
    alice_pub_bytes = serialize_public_key(alice_ecdh_pub)
    alice_sig = ecdsa_sign(alice_id_priv, alice_pub_bytes)

    # Bob validates Alice's handshake and derives session
    bob_key, bob_sid = validate_and_complete_handshake(
        receiver_ephemeral_priv=bob_ecdh_priv,
        peer_ephemeral_pub=alice_ecdh_pub,
        peer_ephemeral_pub_bytes=alice_pub_bytes,
        peer_signature=alice_sig,
        peer_identity_pub=alice_id_pub,
    )

    # Verify matching derivation from Alice's side
    alice_key, alice_sid = derive_session(alice_ecdh_priv, bob_ecdh_pub)
    assert bob_key == alice_key
    assert bob_sid == alice_sid


def test_validate_and_complete_handshake_aborts_on_mitm():
    # Long-term identities
    alice_id_priv, alice_id_pub = generate_identity_keypair()
    mallory_id_priv, mallory_id_pub = generate_identity_keypair()  # MITM Attacker

    # Alice creates legitimate ephemeral ECDH key
    alice_ecdh_priv, alice_ecdh_pub = generate_keypair()
    alice_pub_bytes = serialize_public_key(alice_ecdh_pub)

    # Mallory tampers: replaces with Mallory's ephemeral ECDH key or bogus signature
    mallory_ecdh_priv, mallory_ecdh_pub = generate_keypair()
    mallory_pub_bytes = serialize_public_key(mallory_ecdh_pub)
    # Mallory signs with Mallory's key instead of Alice's
    bogus_sig = ecdsa_sign(mallory_id_priv, mallory_pub_bytes)

    bob_ecdh_priv, _ = generate_keypair()

    # Bob receives Mallory's substituted key claiming to be Alice
    with pytest.raises(ValueError, match="Handshake aborted: Peer signature verification failed"):
        validate_and_complete_handshake(
            receiver_ephemeral_priv=bob_ecdh_priv,
            peer_ephemeral_pub=mallory_ecdh_pub,
            peer_ephemeral_pub_bytes=mallory_pub_bytes,
            peer_signature=bogus_sig,
            peer_identity_pub=alice_id_pub,  # Bob checks against Alice's identity
        )


def test_compute_shared_secret_p256_returns_32_bytes():
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    secret_ab = compute_shared_secret(alice_priv, bob_pub)
    secret_ba = compute_shared_secret(bob_priv, alice_pub)

    assert isinstance(secret_ab, bytes)
    assert len(secret_ab) == 32
    assert secret_ab == secret_ba


def test_compute_shared_secret_rejects_non_p256_curve():
    alice_priv, alice_pub = generate_keypair()
    foreign_priv = ec.generate_private_key(ec.SECP384R1())
    foreign_pub = foreign_priv.public_key()

    with pytest.raises(ValueError, match="Expected secp256r1 curve, got secp384r1"):
        compute_shared_secret(alice_priv, foreign_pub)

    with pytest.raises(ValueError, match="Expected secp256r1 curve, got secp384r1"):
        compute_shared_secret(foreign_priv, alice_pub)


def test_deserialize_public_key_rejects_malformed_truncated_and_unsupported():
    with pytest.raises(ValueError):
        deserialize_public_key(b"not a valid pem")

    corrupted_pem = b"-----BEGIN PUBLIC KEY-----\ngarbage\n-----END PUBLIC KEY-----\n"
    with pytest.raises(ValueError):
        deserialize_public_key(corrupted_pem)

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


def test_deserialize_private_key_rejects_malformed_truncated_and_unsupported():
    with pytest.raises(ValueError):
        deserialize_private_key(b"not a valid pem")

    truncated_pem = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEH"
    with pytest.raises(ValueError):
        deserialize_private_key(truncated_pem)

    foreign_priv = ec.generate_private_key(ec.SECP384R1())
    foreign_priv_pem = foreign_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(ValueError, match="Expected secp256r1 curve, got secp384r1"):
        deserialize_private_key(foreign_priv_pem)

    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_priv_pem = rsa_priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(TypeError, match="The provided key is not an EC private key."):
        deserialize_private_key(rsa_priv_pem)

    with pytest.raises(TypeError, match="Private key data must be bytes-like."):
        deserialize_private_key("not-bytes-string")


def test_handshake_rejects_valid_signature_over_different_ephemeral_key():
    alice_id_priv, alice_id_pub = generate_identity_keypair()
    bob_ecdh_priv, _ = generate_keypair()

    # Alice creates ephemeral key A and signs it
    alice_ecdh_priv_a, alice_ecdh_pub_a = generate_keypair()
    alice_pub_bytes_a = serialize_public_key(alice_ecdh_pub_a)
    alice_sig_a = ecdsa_sign(alice_id_priv, alice_pub_bytes_a)

    # Mallory presents a different ephemeral key B, but reuses signature from key A
    _, mallory_ecdh_pub_b = generate_keypair()
    mallory_pub_bytes_b = serialize_public_key(mallory_ecdh_pub_b)

    with pytest.raises(ValueError, match="Handshake aborted: Peer signature verification failed"):
        validate_and_complete_handshake(
            receiver_ephemeral_priv=bob_ecdh_priv,
            peer_ephemeral_pub=mallory_ecdh_pub_b,
            peer_ephemeral_pub_bytes=mallory_pub_bytes_b,
            peer_signature=alice_sig_a,
            peer_identity_pub=alice_id_pub,
        )


def test_handshake_rejects_mismatched_public_key_and_bytes():
    alice_id_priv, alice_id_pub = generate_identity_keypair()
    bob_ecdh_priv, _ = generate_keypair()

    alice_ecdh_priv_a, alice_ecdh_pub_a = generate_keypair()
    alice_pub_bytes_a = serialize_public_key(alice_ecdh_pub_a)
    alice_sig_a = ecdsa_sign(alice_id_priv, alice_pub_bytes_a)

    _, unverified_key_b = generate_keypair()

    # Attacker passes key B as public key object, but passes key A's bytes (which match the signature)
    with pytest.raises(ValueError, match="Handshake aborted: Peer public key does not match signed bytes"):
        validate_and_complete_handshake(
            receiver_ephemeral_priv=bob_ecdh_priv,
            peer_ephemeral_pub=unverified_key_b,
            peer_ephemeral_pub_bytes=alice_pub_bytes_a,
            peer_signature=alice_sig_a,
            peer_identity_pub=alice_id_pub,
        )


def test_handshake_aborts_before_shared_secret_derivation(monkeypatch):
    alice_id_priv, alice_id_pub = generate_identity_keypair()
    bob_ecdh_priv, _ = generate_keypair()
    alice_ecdh_priv, alice_ecdh_pub = generate_keypair()
    alice_pub_bytes = serialize_public_key(alice_ecdh_pub)
    bogus_sig = b"X" * 64

    call_count = {"derive_session": 0, "compute_shared_secret": 0}

    import crypto.ecdh as ecdh_mod

    orig_derive = ecdh_mod.derive_session
    orig_compute = ecdh_mod.compute_shared_secret

    def spy_derive(*args, **kwargs):
        call_count["derive_session"] += 1
        return orig_derive(*args, **kwargs)

    def spy_compute(*args, **kwargs):
        call_count["compute_shared_secret"] += 1
        return orig_compute(*args, **kwargs)

    monkeypatch.setattr(ecdh_mod, "derive_session", spy_derive)
    monkeypatch.setattr(ecdh_mod, "compute_shared_secret", spy_compute)

    with pytest.raises(ValueError, match="Handshake aborted: Peer signature verification failed"):
        validate_and_complete_handshake(
            receiver_ephemeral_priv=bob_ecdh_priv,
            peer_ephemeral_pub=alice_ecdh_pub,
            peer_ephemeral_pub_bytes=alice_pub_bytes,
            peer_signature=bogus_sig,
            peer_identity_pub=alice_id_pub,
        )

    # Invariant: Neither shared secret computation nor session derivation was reached
    assert call_count["derive_session"] == 0
    assert call_count["compute_shared_secret"] == 0
