"""RSA-2048 key generation and OAEP encryption for Romora (sender side).

Parameters are fixed by Guardrails.md section 8: 2048-bit key, e = 65537,
OAEP with MGF1-SHA256, SHA-256 hash, empty label.
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

RSA_KEY_BITS = 2048
RSA_PUBLIC_EXPONENT = 65537
RSA_CIPHERTEXT_LEN = RSA_KEY_BITS // 8  # 256 bytes
# k - 2*hLen - 2 = 256 - 2*32 - 2
MAX_MESSAGE_BYTES = 190


def oaep_padding() -> padding.OAEP:
    """Return the project-wide OAEP padding (MGF1-SHA256, SHA-256, empty label)."""
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def generate_keypair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generate an RSA-2048 key pair with e = 65537."""
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT, key_size=RSA_KEY_BITS
    )
    return private_key, private_key.public_key()


def encrypt(public_key: rsa.RSAPublicKey, message: str | bytes) -> bytes:
    """Encrypt a message with RSA-OAEP and return the 256-byte ciphertext.

    A str is encoded as UTF-8. The limit applies to the encoded bytes.

    Raises:
        TypeError: If the key or message has the wrong type.
        ValueError: If the message is empty, longer than 190 bytes, or the key
            is not a 2048-bit RSA key.
    """
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Public key must be an RSAPublicKey instance.")
    if public_key.key_size != RSA_KEY_BITS:
        raise ValueError(f"RSA key must be {RSA_KEY_BITS} bits.")

    if isinstance(message, str):
        data = message.encode("utf-8")
    elif isinstance(message, (bytes, bytearray, memoryview)):
        data = bytes(message)
    else:
        raise TypeError("Message must be bytes or str.")

    if not data:
        raise ValueError("Message must not be empty.")
    if len(data) > MAX_MESSAGE_BYTES:
        raise ValueError(
            f"Message too long: {len(data)} bytes (maximum {MAX_MESSAGE_BYTES})."
        )

    return public_key.encrypt(data, oaep_padding())


def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
    """Serialize an RSA public key in SubjectPublicKeyInfo PEM format."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(data: bytes) -> rsa.RSAPublicKey:
    """Deserialize an RSA public key from PEM bytes."""
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, rsa.RSAPublicKey):
        raise TypeError("The provided key is not an RSA public key.")
    return key


def serialize_private_key(private_key: rsa.RSAPrivateKey) -> bytes:
    """Serialize an RSA private key as unencrypted PKCS#8 PEM (keep it git-ignored)."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def deserialize_private_key(data: bytes) -> rsa.RSAPrivateKey:
    """Deserialize an RSA private key from PKCS#8 PEM bytes."""
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("The provided key is not an RSA private key.")
    return key


def public_key_fingerprint(public_key: rsa.RSAPublicKey, *, as_hex: bool = True) -> str | bytes:
    """Return the SHA-256 fingerprint of the DER SubjectPublicKeyInfo bytes."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    digest = hashlib.sha256(der).digest()
    return digest.hex() if as_hex else digest
