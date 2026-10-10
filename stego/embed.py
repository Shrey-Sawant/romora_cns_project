"""Embed payload bytes into PNG images using one LSB per RGB channel."""

from __future__ import annotations

from io import BytesIO

import numpy as np
from PIL import Image, UnidentifiedImageError


def _payload_bits(payload: bytes) -> np.ndarray:
    """Return payload bits in network (most-significant-bit-first) order."""
    return np.unpackbits(np.frombuffer(payload, dtype=np.uint8), bitorder="big")


def embed(cover_png: bytes, payload: bytes) -> bytes:
    """Embed a serialized payload in a PNG and return the stego-image as PNG bytes.

    Payload bytes are written MSB first into the red, green, and blue channel
    LSBs in row-major pixel order. An RGBA image's alpha channel is untouched.
    The payload is embedded as supplied; its framing/header belongs to the
    payload-format layer and is not added or changed here.

    Raises:
        TypeError: If the cover or payload is not bytes-like.
        ValueError: If the image is invalid, unsupported, or too small.
    """
    if not isinstance(cover_png, (bytes, bytearray, memoryview)):
        raise TypeError("Cover image must be PNG bytes.")
    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("Payload must be bytes.")

    payload = bytes(payload)
    if not payload:
        raise ValueError("Payload must not be empty.")

    try:
        with Image.open(BytesIO(cover_png)) as image:
            if image.format != "PNG":
                raise ValueError("Cover image must be a PNG.")
            if image.mode not in ("RGB", "RGBA"):
                raise ValueError("Cover image must use 8-bit RGB or RGBA channels.")
            image.load()
            pixels = np.asarray(image, dtype=np.uint8).copy()
    except (UnidentifiedImageError, OSError) as exc:
        raise ValueError("Cover image must be a valid PNG image.") from exc

    height, width, channels = pixels.shape
    payload_bits = _payload_bits(payload)
    capacity_bits = width * height * 3
    if payload_bits.size > capacity_bits:
        raise ValueError("Image too small for payload.")

    # RGB slicing is copied and assigned back so this also works for RGBA,
    # where the color channels are not contiguous in the source array.
    rgb = pixels[:, :, :3].copy().reshape(-1)
    rgb[: payload_bits.size] = (rgb[: payload_bits.size] & 0xFE) | payload_bits
    pixels[:, :, :3] = rgb.reshape(height, width, 3)

    output = BytesIO()
    Image.fromarray(pixels).save(output, format="PNG")
    return output.getvalue()
