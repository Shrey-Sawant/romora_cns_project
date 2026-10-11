import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.ecdh import (
    DERIVED_KEY_LENGTH,
    SESSION_ID_INFO,
    SESSION_KEY_INFO,
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


def test_session_derivation_contract_constants():
    """Verify production constants strictly match Guardrails Option A specification."""
    assert SESSION_KEY_INFO == b"romora-v1-session"
    assert SESSION_ID_INFO == b"romora-v1-sid"
    assert DERIVED_KEY_LENGTH == 32


def test_session_derivation_matches_independent_hkdf_oracle():
    """Independently verify session_key and session_id against direct HKDF-SHA256 calculations."""
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    # Raw ECDH shared secret computed via cryptography's exchange
    raw_secret_ab = alice_priv.exchange(ec.ECDH(), bob_pub)
    raw_secret_ba = bob_priv.exchange(ec.ECDH(), alice_pub)
    assert raw_secret_ab == raw_secret_ba

    # Ground-truth oracle HKDF instances computed directly with documented parameters
    oracle_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"romora-v1-session",
    ).derive(raw_secret_ab)

    oracle_sid = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"romora-v1-sid",
    ).derive(raw_secret_ab)

    # 1. Verify individual derivation helpers against oracle
    derived_key = derive_session_key(raw_secret_ab)
    derived_sid = derive_session_id(raw_secret_ab)

    assert derived_key == oracle_key
    assert derived_sid == oracle_sid

    # 2. Verify joint derive_session helper matches oracle for both Alice and Bob
    alice_key, alice_sid = derive_session(alice_priv, bob_pub)
    bob_key, bob_sid = derive_session(bob_priv, alice_pub)

    assert alice_key == oracle_key
    assert alice_sid == oracle_sid
    assert bob_key == oracle_key
    assert bob_sid == oracle_sid

    # 3. Structural invariant: 32 bytes each, distinct outputs
    assert len(oracle_key) == 32
    assert len(oracle_sid) == 32
    assert oracle_key != oracle_sid


def test_session_derivation_does_not_chain_key_into_id():
    """Verify Option A non-chaining contract: session_id is not derived by chaining session_key."""
    alice_priv, alice_pub = generate_keypair()
    bob_priv, bob_pub = generate_keypair()

    session_key, session_id = derive_session(alice_priv, bob_pub)

    # In Option B (hierarchical derivation), session_id would be derived from session_key
    chained_id = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"romora-v1-sid",
    ).derive(session_key)

    # Option A contract invariant: session_id must not equal chained_id
    assert session_id != chained_id


def test_session_derivation_domain_separation():
    """Verify domain separation between distinct HKDF info tags on the same shared secret."""
    raw_secret = b"\x5a" * 32

    key = derive_session_key(raw_secret)
    sid = derive_session_id(raw_secret)

    # Alternate context tags on the same raw secret
    alt_derivation_1 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"romora-v1-other",
    ).derive(raw_secret)

    alt_derivation_2 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"",
    ).derive(raw_secret)

    # All outputs must be distinct from each other
    derivation_set = {key, sid, alt_derivation_1, alt_derivation_2}
    assert len(derivation_set) == 4


def test_session_derivation_deterministic_for_fixed_secret():
    """Verify deterministic repeatability against a fixed 32-byte shared secret."""
    fixed_secret = bytes(range(32))  # 0x00, 0x01, ..., 0x1f

    expected_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"romora-v1-session",
    ).derive(fixed_secret)

    expected_sid = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"romora-v1-sid",
    ).derive(fixed_secret)

    # Derive multiple times to ensure strict deterministic purity
    for _ in range(3):
        assert derive_session_key(fixed_secret) == expected_key
        assert derive_session_id(fixed_secret) == expected_sid


def test_session_derivation_rejects_invalid_input_types():
    """Verify derive_session_key and derive_session_id reject non-bytes-like inputs."""
    invalid_inputs = [None, 12345, "a_secret_string", [1, 2, 3], {"secret": b"bytes"}]

    for invalid in invalid_inputs:
        with pytest.raises(TypeError, match="Shared secret must be bytes-like."):
            derive_session_key(invalid)
        with pytest.raises(TypeError, match="Shared secret must be bytes-like."):
            derive_session_id(invalid)


def test_session_derivation_accepts_bytearray_and_memoryview():
    """Verify derive_session_key and derive_session_id accept bytearray and memoryview inputs."""
    raw_secret = b"\x37" * 32

    expected_key = derive_session_key(raw_secret)
    expected_sid = derive_session_id(raw_secret)

    # bytearray input
    ba_secret = bytearray(raw_secret)
    assert derive_session_key(ba_secret) == expected_key
    assert derive_session_id(ba_secret) == expected_sid

    # memoryview input
    mv_secret = memoryview(raw_secret)
    assert derive_session_key(mv_secret) == expected_key
    assert derive_session_id(mv_secret) == expected_sid


def test_derive_session_rejects_invalid_key_types_and_curves():
    """Verify derive_session enforces P-256 curve and key types on both operands."""
    alice_priv, alice_pub = generate_keypair()
    foreign_priv = ec.generate_private_key(ec.SECP384R1())
    foreign_pub = foreign_priv.public_key()
    rsa_priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub = rsa_priv.public_key()

    # Invalid types
    with pytest.raises(TypeError, match="Private key must be an EllipticCurvePrivateKey instance."):
        derive_session(rsa_priv, alice_pub)
    with pytest.raises(TypeError, match="Private key must be an EllipticCurvePrivateKey instance."):
        derive_session("not-a-key", alice_pub)
    with pytest.raises(TypeError, match="Peer public key must be an EllipticCurvePublicKey instance."):
        derive_session(alice_priv, rsa_pub)
    with pytest.raises(TypeError, match="Peer public key must be an EllipticCurvePublicKey instance."):
        derive_session(alice_priv, 12345)

    # Curve mismatch
    with pytest.raises(ValueError, match="Expected secp256r1 curve, got secp384r1"):
        derive_session(foreign_priv, alice_pub)
    with pytest.raises(ValueError, match="Expected secp256r1 curve, got secp384r1"):
        derive_session(alice_priv, foreign_pub)
