import math
from io import BytesIO
import numpy as np
from PIL import Image

from core.receive import receive_message
from core.send import send_message
from crypto.ecdh import derive_session, generate_keypair as generate_ecdh_keypair
from crypto.ecdsa import generate_keypair as generate_ecdsa_keypair
from crypto.rsa_enc import generate_keypair as generate_rsa_keypair


def _calculate_psnr(img_a_bytes: bytes, img_b_bytes: bytes) -> tuple[float, int]:
    """Calculate PSNR and maximum pixel difference between two PNG images."""
    arr_a = np.asarray(Image.open(BytesIO(img_a_bytes)), dtype=np.float64)
    arr_b = np.asarray(Image.open(BytesIO(img_b_bytes)), dtype=np.float64)

    max_diff = int(np.max(np.abs(arr_a - arr_b)))
    mse = np.mean((arr_a - arr_b) ** 2)
    if mse == 0:
        return float("inf"), max_diff
    psnr = 20 * math.log10(255.0 / math.sqrt(mse))
    return psnr, max_diff


def test_full_system_round_trip_and_imperceptibility():
    # 1. Setup Identities
    alice_ecdsa_priv, alice_ecdsa_pub = generate_ecdsa_keypair()
    bob_ecdsa_priv, bob_ecdsa_pub = generate_ecdsa_keypair()
    bob_rsa_priv, bob_rsa_pub = generate_rsa_keypair()

    # 2. Authenticated Handshake
    alice_ecdh_priv, alice_ecdh_pub = generate_ecdh_keypair()
    bob_ecdh_priv, bob_ecdh_pub = generate_ecdh_keypair()
    _, alice_sid = derive_session(alice_ecdh_priv, bob_ecdh_pub)
    _, bob_sid = derive_session(bob_ecdh_priv, alice_ecdh_pub)

    # 3. Create Cover Image
    cover_img = Image.new("RGB", (256, 256), color=(80, 140, 200))
    buf = BytesIO()
    cover_img.save(buf, format="PNG")
    cover_png = buf.getvalue()

    secret_message = "Romora verified covert message: end-to-end operational."

    # 4. Sender Pipeline
    stego_png = send_message(
        message=secret_message,
        cover_png=cover_png,
        session_id=alice_sid,
        sender_ecdsa_priv=alice_ecdsa_priv,
        receiver_rsa_pub=bob_rsa_pub,
    )

    # 5. Measure Imperceptibility (Guardrails.md section 13)
    psnr, max_diff = _calculate_psnr(cover_png, stego_png)
    assert max_diff <= 1, f"Max channel difference {max_diff} exceeded limit 1"
    assert psnr > 50.0, f"PSNR {psnr:.2f} dB is below required threshold"

    # 6. Receiver Pipeline
    result = receive_message(
        stego_png=stego_png,
        session_id=bob_sid,
        sender_ecdsa_pub=alice_ecdsa_pub,
        receiver_rsa_priv=bob_rsa_priv,
    )

    assert result.ok is True
    assert result.signature_verified is True
    assert result.plaintext == secret_message
