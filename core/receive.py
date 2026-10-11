"""End-to-end receiver pipeline for Romora.

Coordinates:
1. LSB extraction from cover/stego PNG (stego/extract.py)
2. Payload parsing and wire format validation (core/payload.py)
3. Sender authenticity & message integrity verification (crypto/ecdsa.py)
4. RSA-2048 OAEP message decryption (crypto/rsa_dec.py)

Strict security guardrail (Guardrails.md section 11):
- Always verify the ECDSA signature BEFORE decrypting.
- If signature verification fails, ABORT immediately. NEVER return or leak plaintext.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from crypto.ecdsa import (
    deserialize_public_key as deserialize_ecdsa_pub,
    verify as ecdsa_verify,
)
from crypto.rsa_dec import (
    decrypt as rsa_decrypt,
    deserialize_private_key as deserialize_rsa_priv,
)
from core.payload import parse_payload
from stego.extract import extract


@dataclass(frozen=True)
class ReceiveResult:
    """Result of processing a received stego image."""

    ok: bool
    signature_verified: bool
    plaintext: Optional[str] = None
    error: Optional[str] = None


class SecurityVerificationError(Exception):
    """Raised when digital signature verification fails."""


def receive_message(
    stego_png: bytes,
    session_id: bytes,
    sender_ecdsa_pub: ec.EllipticCurvePublicKey | bytes,
    receiver_rsa_priv: rsa.RSAPrivateKey | bytes,
    *,
    raise_on_error: bool = False,
) -> ReceiveResult:
    """Execute the complete receiver pipeline.

    Args:
        stego_png: Raw bytes of the stego PNG image.
        session_id: 32-byte session identifier derived from the ECDH handshake.
        sender_ecdsa_pub: Sender's long-term ECDSA public key (object or PEM bytes).
        receiver_rsa_priv: Receiver's RSA-2048 private key (object or PEM bytes).
        raise_on_error: If True, raise an exception on failure instead of returning
            a failed ReceiveResult.

    Returns:
        ReceiveResult with status, verification flag, and decrypted plaintext.

    Raises:
        SecurityVerificationError: If raise_on_error=True and signature verification fails.
        ValueError: If raise_on_error=True and image extraction or decryption fails.
    """
    # 0. Normalize key formats
    if isinstance(sender_ecdsa_pub, (bytes, bytearray, memoryview)):
        sender_ecdsa_pub = deserialize_ecdsa_pub(bytes(sender_ecdsa_pub))
    if isinstance(receiver_rsa_priv, (bytes, bytearray, memoryview)):
        receiver_rsa_priv = deserialize_rsa_priv(bytes(receiver_rsa_priv))

    if not isinstance(session_id, (bytes, bytearray, memoryview)) or len(session_id) != 32:
        err = "Invalid session ID: must be 32 bytes."
        if raise_on_error:
            raise ValueError(err)
        return ReceiveResult(ok=False, signature_verified=False, error=err)

    session_id_bytes = bytes(session_id)

    # 1. Steganography extraction
    try:
        payload_bytes = extract(stego_png)
    except Exception as exc:
        err = f"Stego extraction failed: {exc}"
        if raise_on_error:
            raise ValueError(err) from exc
        return ReceiveResult(ok=False, signature_verified=False, error=err)

    # 2. Wire payload parsing
    try:
        rsa_ciphertext, signature = parse_payload(payload_bytes)
    except Exception as exc:
        err = f"Payload parsing failed: {exc}"
        if raise_on_error:
            raise ValueError(err) from exc
        return ReceiveResult(ok=False, signature_verified=False, error=err)

    # 3. ECDSA Signature verification (CRITICAL GUARDRAIL: BEFORE DECRYPTION)
    signed_data = session_id_bytes + rsa_ciphertext
    is_signature_valid = ecdsa_verify(sender_ecdsa_pub, signed_data, signature)

    if not is_signature_valid:
        # DO NOT PROCEED TO DECRYPTION. HIDE ALL PLAINTEXT.
        err = "Signature verification failed: sender authenticity or message integrity compromised."
        if raise_on_error:
            raise SecurityVerificationError(err)
        return ReceiveResult(
            ok=False,
            signature_verified=False,
            plaintext=None,
            error=err,
        )

    # 4. RSA-2048 OAEP Decryption
    try:
        plaintext = rsa_decrypt(receiver_rsa_priv, rsa_ciphertext, as_str=True)
    except Exception as exc:
        err = f"RSA decryption failed: {exc}"
        if raise_on_error:
            raise ValueError(err) from exc
        return ReceiveResult(
            ok=False,
            signature_verified=True,
            plaintext=None,
            error=err,
        )

    # 5. Success
    return ReceiveResult(
        ok=True,
        signature_verified=True,
        plaintext=plaintext,
        error=None,
    )
