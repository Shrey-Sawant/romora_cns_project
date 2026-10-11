"""ECDH (Elliptic-Curve Diffie-Hellman) key exchange and session derivation for Romora.

Parameters follow Guardrails.md section 6.2 and section 8:
- Curve: P-256 (SECP256R1)
- KDF: HKDF-SHA256
  - Session key info: "romora-v1-session" (32 bytes)
  - Session ID info: "romora-v1-sid" (32 bytes)
"""

from __future__ import annotations

import hashlib
from typing import Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .ecdsa import verify as ecdsa_verify

SESSION_KEY_INFO = b"romora-v1-session"
SESSION_ID_INFO = b"romora-v1-sid"
DERIVED_KEY_LENGTH = 32


def generate_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate an ephemeral P-256 ECDH key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialize an EC public key in SubjectPublicKeyInfo PEM format."""
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("Public key must be an EllipticCurvePublicKey instance.")
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    """Deserialize an EC public key from PEM bytes."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("Public key data must be bytes-like.")
    public_key = serialization.load_pem_public_key(bytes(data))
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("The provided key is not an EC public key.")
    if public_key.curve.name != "secp256r1":
        raise ValueError(f"Expected secp256r1 curve, got {public_key.curve.name}.")
    return public_key


def serialize_private_key(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Serialize an EC private key in PKCS#8 PEM format (unencrypted)."""
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("Private key must be an EllipticCurvePrivateKey instance.")
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key(data: bytes) -> ec.EllipticCurvePrivateKey:
    """Deserialize an EC private key from PKCS#8 PEM bytes."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("Private key data must be bytes-like.")
    private_key = serialization.load_pem_private_key(bytes(data), password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("The provided key is not an EC private key.")
    if private_key.curve.name != "secp256r1":
        raise ValueError(f"Expected secp256r1 curve, got {private_key.curve.name}.")
    return private_key


def public_key_fingerprint(public_key: ec.EllipticCurvePublicKey, *, as_hex: bool = True) -> str | bytes:
    """Return the SHA-256 fingerprint of the DER SubjectPublicKeyInfo bytes."""
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("Public key must be an EllipticCurvePublicKey instance.")
    key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(key_bytes).digest()
    return digest.hex() if as_hex else digest


def compute_shared_secret(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
) -> bytes:
    """Compute the raw ECDH shared secret.

    Security rule: The raw shared secret must never be used directly as a key.
    Always pass through derive_session_key() or derive_session().
    """
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("Private key must be an EllipticCurvePrivateKey instance.")
    if not isinstance(peer_public_key, ec.EllipticCurvePublicKey):
        raise TypeError("Peer public key must be an EllipticCurvePublicKey instance.")

    return private_key.exchange(ec.ECDH(), peer_public_key)


def derive_session_key(shared_secret: bytes) -> bytes:
    """Derive the 32-byte session key from the shared secret using HKDF-SHA256."""
    if not isinstance(shared_secret, (bytes, bytearray, memoryview)):
        raise TypeError("Shared secret must be bytes-like.")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=DERIVED_KEY_LENGTH,
        salt=None,
        info=SESSION_KEY_INFO,
    )
    return hkdf.derive(bytes(shared_secret))


def derive_session_id(shared_secret: bytes) -> bytes:
    """Derive the 32-byte session identifier from the shared secret using HKDF-SHA256."""
    if not isinstance(shared_secret, (bytes, bytearray, memoryview)):
        raise TypeError("Shared secret must be bytes-like.")
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=DERIVED_KEY_LENGTH,
        salt=None,
        info=SESSION_ID_INFO,
    )
    return hkdf.derive(bytes(shared_secret))


def derive_session(
    private_key: ec.EllipticCurvePrivateKey,
    peer_public_key: ec.EllipticCurvePublicKey,
) -> tuple[bytes, bytes]:
    """Compute shared secret and derive both (session_key, session_id)."""
    raw_secret = compute_shared_secret(private_key, peer_public_key)
    session_key = derive_session_key(raw_secret)
    session_id = derive_session_id(raw_secret)
    return session_key, session_id


def validate_and_complete_handshake(
    receiver_ephemeral_priv: ec.EllipticCurvePrivateKey,
    peer_ephemeral_pub: ec.EllipticCurvePublicKey,
    peer_ephemeral_pub_bytes: bytes,
    peer_signature: bytes,
    peer_identity_pub: ec.EllipticCurvePublicKey,
) -> tuple[bytes, bytes]:
    """Receiver-side handshake verification and session derivation.

    Per Guardrails.md section 6.2:
    - Step 3: Each side verifies the peer's signature first.
      If verification fails, abort and do not derive anything.
    - Step 4: Compute ECDH shared secret and derive session keys with HKDF.

    Raises:
        ValueError: If peer signature is invalid (MITM or tampering detected).
    """
    is_valid = ecdsa_verify(peer_identity_pub, peer_ephemeral_pub_bytes, peer_signature)
    if not is_valid:
        raise ValueError("Handshake aborted: Peer signature verification failed (MITM detected).")

    return derive_session(receiver_ephemeral_priv, peer_ephemeral_pub)
