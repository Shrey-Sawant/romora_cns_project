"""ECDSA utilities for Romora using P-256 keys and raw r||s signatures."""

from __future__ import annotations

import hashlib
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature


def generate_keypair() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generate a P-256 ECDSA key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, private_key.public_key()


def _to_bytes(message: str | bytes) -> bytes:
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode("utf-8")
    raise TypeError("Message must be bytes or str.")


def _der_to_raw(signature: bytes) -> bytes:
    """Convert a DER-encoded ECDSA signature to a canonical raw 64-byte r||s form."""
    if len(signature) == 64:
        return signature

    r, s = decode_dss_signature(signature)
    return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")


def _raw_to_der(signature: bytes) -> bytes:
    """Convert a raw 64-byte r||s signature into DER format for verification."""
    if len(signature) != 64:
        raise ValueError("ECDSA signature must be exactly 64 raw bytes (r || s).")

    r = int.from_bytes(signature[:32], byteorder="big")
    s = int.from_bytes(signature[32:], byteorder="big")
    return encode_dss_signature(r, s)


def sign(private_key: ec.EllipticCurvePrivateKey, message: str | bytes) -> bytes:
    """Sign a message using P-256 ECDSA and return the raw 64-byte r||s signature."""
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("Private key must be an EllipticCurvePrivateKey instance.")

    data = _to_bytes(message)
    signature_der = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    return _der_to_raw(signature_der)


def verify(public_key: ec.EllipticCurvePublicKey, message: str | bytes, signature: bytes) -> bool:
    """Verify a raw r||s signature produced by sign()."""
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("Public key must be an EllipticCurvePublicKey instance.")

    data = _to_bytes(message)
    try:
        der_signature = _raw_to_der(signature)
        public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    except (ValueError, InvalidSignature):
        return False


def serialize_private_key(private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Serialize an EC private key in PKCS#8 PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key(data: bytes) -> ec.EllipticCurvePrivateKey:
    """Deserialize an EC private key from PKCS#8 PEM bytes."""
    private_key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise TypeError("The provided key is not an EC private key.")
    return private_key


def serialize_public_key(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """Serialize an EC public key in standard PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(data: bytes) -> ec.EllipticCurvePublicKey:
    """Deserialize an EC public key from PEM bytes."""
    public_key = serialization.load_pem_public_key(data)
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise TypeError("The provided key is not an EC public key.")
    return public_key


def public_key_fingerprint(public_key: ec.EllipticCurvePublicKey, *, as_hex: bool = True) -> str | bytes:
    """Return the SHA-256 fingerprint of the subject public key bytes."""
    key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(key_bytes).digest()
    if as_hex:
        return digest.hex()
    return digest
