"""Extract payload bytes from PNG images using one LSB per RGB channel."""

from __future__ import annotations

from io import BytesIO
import struct

import numpy as np
from PIL import Image, UnidentifiedImageError

ROMORA_MAGIC = b"RMRA"
ROMORA_VERSION = 1
HEADER_FORMAT = ">4sBHH"  # magic(4), version(1), ct_len(2), sig_len(2)
HEADER_LEN = struct.calcsize(HEADER_FORMAT)  # 9 bytes
HEADER_BITS = HEADER_LEN * 8  # 72 bits


def extract(stego_png: bytes) -> bytes:
    """Extract an embedded Romora payload from a PNG stego-image.

    Reads LSBs from red, green, and blue channels in row-major order (ignoring alpha),
    parses the 9-byte Romora header to determine payload length, and returns the
    full payload bytes.

    Raises:
        TypeError: If stego_png is not bytes-like.
        ValueError: If the image is not a valid PNG, unsupported mode, too small,
            or contains no valid Romora header.
    """
    if not isinstance(stego_png, (bytes, bytearray, memoryview)):
        raise TypeError("Stego image must be PNG bytes.")

    try:
        with Image.open(BytesIO(stego_png)) as image:
            if image.format != "PNG":
                raise ValueError(f"Stego image must be a PNG (got {image.format or 'unknown'}).")
            if image.mode not in ("RGB", "RGBA"):
                raise ValueError(f"Stego image must use 8-bit RGB or RGBA channels (got {image.mode}).")
            image.load()
            pixels = np.asarray(image, dtype=np.uint8)
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError("Stego image must be a valid PNG image.") from exc

    # Extract LSBs from R, G, B channels in row-major order (skipping alpha)
    rgb = pixels[:, :, :3].reshape(-1)
    if rgb.size < HEADER_BITS:
        raise ValueError("Image is too small to contain a Romora header.")

    lsb_bits = rgb & 0x01

    # Extract and parse 9-byte header
    header_bits = lsb_bits[:HEADER_BITS]
    header_bytes = np.packbits(header_bits, bitorder="big").tobytes()

    magic, version, ct_len, sig_len = struct.unpack(HEADER_FORMAT, header_bytes)
    if magic != ROMORA_MAGIC:
        raise ValueError(f"No Romora payload found in image: invalid magic {magic!r}.")
    if version != ROMORA_VERSION:
        raise ValueError(f"Unsupported payload version: {version}.")

    total_payload_bytes = HEADER_LEN + ct_len + sig_len
    total_payload_bits = total_payload_bytes * 8

    if lsb_bits.size < total_payload_bits:
        raise ValueError(
            f"Stego image capacity ({lsb_bits.size} bits) is smaller than declared payload ({total_payload_bits} bits)."
        )

    payload_bits = lsb_bits[:total_payload_bits]
    return np.packbits(payload_bits, bitorder="big").tobytes()
