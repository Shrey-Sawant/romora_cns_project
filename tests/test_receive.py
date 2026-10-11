from io import BytesIO
import pytest
from PIL import Image

from core.receive import ReceiveResult, SecurityVerificationError, receive_message
from core.send import send_message
from crypto.ecdh import derive_session, generate_keypair as generate_ecdh_keypair
from crypto.ecdsa import generate_keypair as generate_ecdsa_keypair
from crypto.rsa_enc import generate_keypair as generate_rsa_keypair


def _create_cover_png(width: int = 128, height: int = 128) -> bytes:
    img = Image.new("RGB", (width, height), color=(100, 150, 200))
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_receive_round_trip_success():
    # Long-term keys
    alice_ecdsa_priv, alice_ecdsa_pub = generate_ecdsa_keypair()
    bob_ecdsa_priv, bob_ecdsa_pub = generate_ecdsa_keypair()
    bob_rsa_priv, bob_rsa_pub = generate_rsa_keypair()

    # Handshake
    alice_ecdh_priv, alice_ecdh_pub = generate_ecdh_keypair()
    bob_ecdh_priv, bob_ecdh_pub = generate_ecdh_keypair()
    alice_key, alice_sid = derive_session(alice_ecdh_priv, bob_ecdh_pub)
    bob_key, bob_sid = derive_session(bob_ecdh_priv, alice_ecdh_pub)
    assert alice_sid == bob_sid

    message = "Secret rendezvous at dawn. Bring coordinates."
    cover = _create_cover_png()

    stego_png = send_message(
        message=message,
        cover_png=cover,
        session_id=alice_sid,
        sender_ecdsa_priv=alice_ecdsa_priv,
        receiver_rsa_pub=bob_rsa_pub,
    )

    result = receive_message(
        stego_png=stego_png,
        session_id=bob_sid,
        sender_ecdsa_pub=alice_ecdsa_pub,
        receiver_rsa_priv=bob_rsa_priv,
    )

    assert result.ok is True
    assert result.signature_verified is True
    assert result.plaintext == message
    assert result.error is None


def test_receive_rejects_tampered_stego_image_and_leaks_no_plaintext():
    alice_ecdsa_priv, alice_ecdsa_pub = generate_ecdsa_keypair()
    bob_rsa_priv, bob_rsa_pub = generate_rsa_keypair()
    session_id = b"S" * 32
    message = "Highly sensitive confidential data."

    stego_png = send_message(
        message=message,
        cover_png=_create_cover_png(),
        session_id=session_id,
        sender_ecdsa_priv=alice_ecdsa_priv,
        receiver_rsa_pub=bob_rsa_pub,
    )

    # Attacker tampers with pixel bits in the image
    img = Image.open(BytesIO(stego_png))
    import numpy as np
    pixels = np.asarray(img, dtype=np.uint8).copy()
    # Flip bit in payload region (after 9-byte header = 72 bits)
    # Target pixel around pixel 50
    pixels[0, 50, 0] ^= 0x01
    tampered_buf = BytesIO()
    Image.fromarray(pixels).save(tampered_buf, format="PNG")
    tampered_png = tampered_buf.getvalue()

    result = receive_message(
        stego_png=tampered_png,
        session_id=session_id,
        sender_ecdsa_pub=alice_ecdsa_pub,
        receiver_rsa_priv=bob_rsa_priv,
    )

    # CRITICAL SECURITY GUARDRAIL CHECK:
    assert result.ok is False
    assert result.signature_verified is False
    assert result.plaintext is None  # MUST NEVER BE EXPOSED!
    assert "Signature verification failed" in result.error


def test_receive_rejects_wrong_sender_public_key():
    alice_ecdsa_priv, alice_ecdsa_pub = generate_ecdsa_keypair()
    mallory_ecdsa_priv, mallory_ecdsa_pub = generate_ecdsa_keypair()
    bob_rsa_priv, bob_rsa_pub = generate_rsa_keypair()
    session_id = b"S" * 32
    message = "Genuine message from Alice."

    stego_png = send_message(
        message=message,
        cover_png=_create_cover_png(),
        session_id=session_id,
        sender_ecdsa_priv=alice_ecdsa_priv,
        receiver_rsa_pub=bob_rsa_pub,
    )

    # Receiver validates against Mallory's key instead of Alice's
    result = receive_message(
        stego_png=stego_png,
        session_id=session_id,
        sender_ecdsa_pub=mallory_ecdsa_pub,
        receiver_rsa_priv=bob_rsa_priv,
    )

    assert result.ok is False
    assert result.signature_verified is False
    assert result.plaintext is None


def test_receive_rejects_wrong_session_id():
    alice_ecdsa_priv, alice_ecdsa_pub = generate_ecdsa_keypair()
    bob_rsa_priv, bob_rsa_pub = generate_rsa_keypair()
    alice_session_id = b"A" * 32
    wrong_session_id = b"W" * 32

    stego_png = send_message(
        message="Session test message",
        cover_png=_create_cover_png(),
        session_id=alice_session_id,
        sender_ecdsa_priv=alice_ecdsa_priv,
        receiver_rsa_pub=bob_rsa_pub,
    )

    result = receive_message(
        stego_png=stego_png,
        session_id=wrong_session_id,
        sender_ecdsa_pub=alice_ecdsa_pub,
        receiver_rsa_priv=bob_rsa_priv,
    )

    assert result.ok is False
    assert result.signature_verified is False
    assert result.plaintext is None


def test_receive_wrong_receiver_rsa_key_fails_decryption():
    alice_ecdsa_priv, alice_ecdsa_pub = generate_ecdsa_keypair()
    bob_rsa_priv, bob_rsa_pub = generate_rsa_keypair()
    charlie_rsa_priv, _ = generate_rsa_keypair()
    session_id = b"S" * 32

    # Encrypted specifically for Bob
    stego_png = send_message(
        message="Confidential for Bob",
        cover_png=_create_cover_png(),
        session_id=session_id,
        sender_ecdsa_priv=alice_ecdsa_priv,
        receiver_rsa_pub=bob_rsa_pub,
    )

    # Charlie attempts to decrypt with Charlie's RSA key
    result = receive_message(
        stego_png=stego_png,
        session_id=session_id,
        sender_ecdsa_pub=alice_ecdsa_pub,
        receiver_rsa_priv=charlie_rsa_priv,
    )

    assert result.ok is False
    assert result.signature_verified is True  # Signature was indeed valid
    assert result.plaintext is None  # Decryption failed, no plaintext
    assert "RSA decryption failed" in result.error


def test_receive_max_190_byte_boundary():
    alice_ecdsa_priv, alice_ecdsa_pub = generate_ecdsa_keypair()
    bob_rsa_priv, bob_rsa_pub = generate_rsa_keypair()
    session_id = b"S" * 32
    max_message = "M" * 190

    stego_png = send_message(
        message=max_message,
        cover_png=_create_cover_png(),
        session_id=session_id,
        sender_ecdsa_priv=alice_ecdsa_priv,
        receiver_rsa_pub=bob_rsa_pub,
    )

    result = receive_message(
        stego_png=stego_png,
        session_id=session_id,
        sender_ecdsa_pub=alice_ecdsa_pub,
        receiver_rsa_priv=bob_rsa_priv,
    )

    assert result.ok is True
    assert result.plaintext == max_message
