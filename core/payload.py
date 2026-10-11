"""Binary payload building and parsing for Romora.

Contract defined in Guardrails.md section 7:
All integers are big-endian:
- magic: 4 B (ASCII 'RMRA')
- version: 1 B (0x01)
- ct_len: 2 B (256 for RSA-2048)
- sig_len: 2 B (64 for raw P-256 r||s)
- rsa_ciphertext: ct_len B
- signature: sig_len B

Total size is fixed at 329 bytes.
"""

from __future__ import annotations

import struct

MAGIC = b"RMRA"
VERSION = 1
EXPECTED_CT_LEN = 256
EXPECTED_SIG_LEN = 64
HEADER_FORMAT = ">4sBHH"  # 4 bytes magic, 1 byte version, 2 bytes ct_len, 2 bytes sig_len
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 9 bytes
TOTAL_PAYLOAD_SIZE = HEADER_SIZE + EXPECTED_CT_LEN + EXPECTED_SIG_LEN  # 329 bytes


def build_payload(rsa_ciphertext: bytes, signature: bytes) -> bytes:
    """Pack an RSA ciphertext and ECDSA signature into the canonical wire payload."""
    if not isinstance(rsa_ciphertext, (bytes, bytearray, memoryview)):
        raise TypeError("RSA ciphertext must be bytes-like.")
    if not isinstance(signature, (bytes, bytearray, memoryview)):
        raise TypeError("Signature must be bytes-like.")

    ct_bytes = bytes(rsa_ciphertext)
    sig_bytes = bytes(signature)

    if len(ct_bytes) != EXPECTED_CT_LEN:
        raise ValueError(
            f"Expected RSA ciphertext of {EXPECTED_CT_LEN} bytes, got {len(ct_bytes)}."
        )
    if len(sig_bytes) != EXPECTED_SIG_LEN:
        raise ValueError(
            f"Expected ECDSA signature of {EXPECTED_SIG_LEN} bytes, got {len(sig_bytes)}."
        )

    header = struct.pack(HEADER_FORMAT, MAGIC, VERSION, len(ct_bytes), len(sig_bytes))
    return header + ct_bytes + sig_bytes


def parse_payload(payload_bytes: bytes) -> tuple[bytes, bytes]:
    """Parse and validate a Romora payload into (rsa_ciphertext, signature).

    Raises:
        TypeError: If payload_bytes is not bytes-like.
        ValueError: If header magic is invalid, version is unsupported, length
            is truncated or mismatched, or fields do not match expected sizes.
    """
    if not isinstance(payload_bytes, (bytes, bytearray, memoryview)):
        raise TypeError("Payload must be bytes-like.")

    raw = bytes(payload_bytes)
    if len(raw) < HEADER_SIZE:
        raise ValueError(
            f"Payload truncated: received {len(raw)} bytes, header requires at least {HEADER_SIZE} bytes."
        )

    magic, version, ct_len, sig_len = struct.unpack_from(HEADER_FORMAT, raw, 0)

    if magic != MAGIC:
        raise ValueError(f"Invalid payload magic identifier: expected {MAGIC!r}, got {magic!r}.")
    if version != VERSION:
        raise ValueError(f"Unsupported payload version: expected {VERSION}, got {version}.")

    expected_total = HEADER_SIZE + ct_len + sig_len
    if len(raw) != expected_total:
        raise ValueError(
            f"Payload size mismatch: declared {expected_total} bytes, received {len(raw)} bytes."
        )

    if ct_len != EXPECTED_CT_LEN:
        raise ValueError(
            f"Invalid ciphertext length: expected {EXPECTED_CT_LEN} bytes, got {ct_len}."
        )
    if sig_len != EXPECTED_SIG_LEN:
        raise ValueError(
            f"Invalid signature length: expected {EXPECTED_SIG_LEN} bytes, got {sig_len}."
        )

    offset = HEADER_SIZE
    ciphertext = raw[offset : offset + ct_len]
    signature = raw[offset + ct_len : offset + ct_len + sig_len]

    return ciphertext, signature
