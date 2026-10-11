from io import BytesIO
import pytest
from PIL import Image

from core.payload import build_payload
from stego.embed import embed
from stego.extract import extract


def _create_cover_png(width: int = 64, height: int = 64, mode: str = "RGB") -> bytes:
    """Helper to generate a clean PNG test image."""
    img = Image.new(mode, (width, height), color=(120, 150, 180) if mode == "RGB" else (120, 150, 180, 255))
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_embed_and_extract_round_trip_rgb():
    cover = _create_cover_png(64, 64, "RGB")
    payload = build_payload(b"C" * 256, b"S" * 64)

    stego_bytes = embed(cover, payload)
    extracted_payload = extract(stego_bytes)

    assert extracted_payload == payload


def test_embed_and_extract_round_trip_rgba():
    cover = _create_cover_png(64, 64, "RGBA")
    payload = build_payload(b"K" * 256, b"Q" * 64)

    stego_bytes = embed(cover, payload)
    extracted_payload = extract(stego_bytes)

    assert extracted_payload == payload


def test_extract_rejects_non_png_data():
    with pytest.raises(ValueError, match="Stego image must be a valid PNG image"):
        extract(b"Not a real PNG file")


def test_extract_rejects_jpeg_image():
    img = Image.new("RGB", (64, 64), color="blue")
    buf = BytesIO()
    img.save(buf, format="JPEG")
    jpeg_bytes = buf.getvalue()

    with pytest.raises(ValueError, match="Stego image must be a PNG"):
        extract(jpeg_bytes)


def test_extract_rejects_unmodified_carrier_image():
    cover = _create_cover_png(64, 64, "RGB")

    with pytest.raises(ValueError, match="No Romora payload found in image"):
        extract(cover)
