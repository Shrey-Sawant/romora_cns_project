import pytest

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
