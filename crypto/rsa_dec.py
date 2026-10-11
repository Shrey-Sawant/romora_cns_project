"""RSA-2048 OAEP decryption for Romora (receiver side).

Parameters are fixed by Guardrails.md section 8:
- RSA-2048 key (256 bytes)
- OAEP with MGF1-SHA256, SHA-256 hash, empty label
- Reject invalid ciphertext with a clean ValueError (do not leak stack trace or key)
"""

from __future__ import annotations

from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import rsa

from .rsa_enc import (
    RSA_CIPHERTEXT_LEN,
    RSA_KEY_BITS,
    deserialize_private_key,
    oaep_padding,
)


def decrypt(
    private_key: rsa.RSAPrivateKey,
    ciphertext: bytes,
    *,
    as_str: bool = True,
) -> str | bytes:
    """Decrypt a 256-byte RSA-OAEP ciphertext using the receiver's private key.

    Args:
        private_key: An RSA-2048 private key.
        ciphertext: The 256-byte ciphertext to decrypt.
        as_str: If True (default), decode the recovered plaintext as UTF-8 string.

    Returns:
        The decrypted plaintext as a string (if as_str=True) or raw bytes.

    Raises:
        TypeError: If key or ciphertext is not of the expected type.
        ValueError: If ciphertext length is incorrect or decryption fails.
    """
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Private key must be an RSAPrivateKey instance.")
    if private_key.key_size != RSA_KEY_BITS:
        raise ValueError(f"RSA key must be {RSA_KEY_BITS} bits.")

    if not isinstance(ciphertext, (bytes, bytearray, memoryview)):
        raise TypeError("Ciphertext must be bytes-like.")
    ciphertext_bytes = bytes(ciphertext)

    if len(ciphertext_bytes) != RSA_CIPHERTEXT_LEN:
        raise ValueError(
            f"Invalid ciphertext length: expected {RSA_CIPHERTEXT_LEN} bytes, got {len(ciphertext_bytes)}."
        )

    try:
        plaintext_bytes = private_key.decrypt(ciphertext_bytes, oaep_padding())
    except Exception as exc:
        # Wrap any OAEP padding failure, key mismatch, or decryption error into a clean ValueError
        raise ValueError("RSA decryption failed: invalid ciphertext or wrong key.") from None

    if as_str:
        try:
            return plaintext_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("Decrypted plaintext is not valid UTF-8.") from exc

    return plaintext_bytes
