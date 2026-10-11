"""End-to-end sender pipeline for Romora.

Coordinates:
1. Message length check (<= 190 bytes)
2. RSA-2048 OAEP encryption with receiver's public key (crypto/rsa_enc.py)
3. Digital signature over (session_id || rsa_ciphertext) with sender's ECDSA key (crypto/ecdsa.py)
4. Wire framing into 329-byte payload (core/payload.py)
5. LSB embedding into cover PNG image (stego/embed.py)
"""

from __future__ import annotations

from cryptography.hazmat.primitives.asymmetric import ec, rsa

from crypto.ecdsa import (
    deserialize_private_key as deserialize_ecdsa_priv,
    sign as ecdsa_sign,
)
from crypto.rsa_enc import (
    MAX_MESSAGE_BYTES,
    deserialize_public_key as deserialize_rsa_pub,
    encrypt as rsa_encrypt,
)
from core.payload import build_payload
from stego.embed import embed


def send_message(
    message: str | bytes,
    cover_png: bytes,
    session_id: bytes,
    sender_ecdsa_priv: ec.EllipticCurvePrivateKey | bytes,
    receiver_rsa_pub: rsa.RSAPublicKey | bytes,
) -> bytes:
    """Execute the complete sender pipeline and return the stego PNG image bytes."""
    # 0. Normalize key formats
    if isinstance(sender_ecdsa_priv, (bytes, bytearray, memoryview)):
        sender_ecdsa_priv = deserialize_ecdsa_priv(bytes(sender_ecdsa_priv))
    if isinstance(receiver_rsa_pub, (bytes, bytearray, memoryview)):
        receiver_rsa_pub = deserialize_rsa_pub(bytes(receiver_rsa_pub))

    if not isinstance(session_id, (bytes, bytearray, memoryview)) or len(session_id) != 32:
        raise ValueError("Invalid session ID: must be exactly 32 bytes.")

    session_id_bytes = bytes(session_id)

    # 1. RSA-2048 OAEP encryption
    rsa_ciphertext = rsa_encrypt(receiver_rsa_pub, message)

    # 2. ECDSA signature over session_id || rsa_ciphertext
    data_to_sign = session_id_bytes + rsa_ciphertext
    signature = ecdsa_sign(sender_ecdsa_priv, data_to_sign)

    # 3. Wire payload framing
    payload = build_payload(rsa_ciphertext, signature)

    # 4. LSB steganography embedding
    stego_png = embed(cover_png, payload)

    return stego_png
