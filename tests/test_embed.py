from io import BytesIO

import numpy as np
import pytest
from PIL import Image

from stego.embed import embed


def _png_bytes(mode: str, size: tuple[int, int], color) -> bytes:
    image = Image.new(mode, size, color)
    output = BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _open_png(data: bytes) -> Image.Image:
    return Image.open(BytesIO(data))


def test_embed_writes_bits_most_significant_first_and_returns_png():
    cover = _png_bytes("RGB", (4, 2), (100, 101, 102))
    payload = b"\x80"

    result = embed(cover, payload)

    with _open_png(result) as stego:
        assert stego.format == "PNG"
        assert stego.mode == "RGB"
        lsb = (np.asarray(stego).reshape(-1)[:8] & 1).tolist()
    assert lsb == [1, 0, 0, 0, 0, 0, 0, 0]


def test_embed_preserves_alpha_and_changes_color_channels_by_at_most_one():
    cover = _png_bytes("RGBA", (8, 4), (100, 101, 102, 77))
    with _open_png(cover) as image:
        original = np.asarray(image).copy()

    result = embed(cover, b"Romora")

    with _open_png(result) as stego:
        assert stego.format == "PNG"
        embedded = np.asarray(stego)
    assert np.array_equal(embedded[:, :, 3], original[:, :, 3])
    assert np.max(np.abs(embedded[:, :, :3].astype(int) - original[:, :, :3])) <= 1


def test_embed_accepts_exact_bit_capacity():
    # Three RGB pixels provide nine bits, enough for one byte.
    cover = _png_bytes("RGB", (3, 1), (0, 0, 0))

    result = embed(cover, b"\xA5")

    with _open_png(result) as stego:
        assert stego.size == (3, 1)


def test_embed_carries_the_frozen_romora_payload_without_extra_framing():
    header = b"RMRA\x01" + (256).to_bytes(2, "big") + (64).to_bytes(2, "big")
    payload = header + bytes(range(256)) + bytes(range(64))
    cover = _png_bytes("RGB", (30, 30), (0, 0, 0))

    result = embed(cover, payload)

    with _open_png(result) as stego:
        embedded_bits = np.asarray(stego).reshape(-1)[: len(payload) * 8] & 1
    assert np.array_equal(embedded_bits, np.unpackbits(np.frombuffer(payload, dtype=np.uint8)))


def test_embed_rejects_payload_over_capacity():
    cover = _png_bytes("RGB", (3, 1), (0, 0, 0))

    with pytest.raises(ValueError, match="Image too small"):
        embed(cover, b"\x00\x00")


def test_embed_rejects_jpeg_and_unsupported_png_mode():
    jpeg_output = BytesIO()
    Image.new("RGB", (8, 8)).save(jpeg_output, format="JPEG")
    gray_png = _png_bytes("L", (8, 8), 128)

    with pytest.raises(ValueError, match="must be a PNG"):
        embed(jpeg_output.getvalue(), b"x")
    with pytest.raises(ValueError, match="RGB or RGBA"):
        embed(gray_png, b"x")


def test_embed_rejects_invalid_image_empty_payload_and_wrong_types():
    with pytest.raises(ValueError, match="valid PNG"):
        embed(b"not an image", b"x")
    with pytest.raises(ValueError, match="must not be empty"):
        embed(_png_bytes("RGB", (8, 8), (0, 0, 0)), b"")
    with pytest.raises(TypeError, match="Cover image"):
        embed("path.png", b"x")
    with pytest.raises(TypeError, match="Payload"):
        embed(_png_bytes("RGB", (8, 8), (0, 0, 0)), "x")
