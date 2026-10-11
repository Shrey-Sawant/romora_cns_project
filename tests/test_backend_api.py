import base64
from io import BytesIO

from fastapi.testclient import TestClient
from PIL import Image

from backend.app import app
from crypto.ecdh import generate_keypair as generate_ecdh_keypair
from crypto.ecdh import serialize_public_key as serialize_ecdh_public_key
from crypto.ecdsa import generate_keypair as generate_ecdsa_keypair
from crypto.ecdsa import serialize_public_key as serialize_ecdsa_public_key, sign

client = TestClient(app)


def _generate_identity():
    response = client.post("/keys/generate")
    assert response.status_code == 200
    return response.json()


def _png_bytes(size=(256, 256)):
    image = Image.new("RGB", size, color=(80, 140, 200))
    stream = BytesIO()
    image.save(stream, format="PNG")
    return stream.getvalue()


def test_key_generation_returns_public_keys_and_fingerprints_only():
    response = client.post("/keys/generate")
    assert response.status_code == 200
    identity = response.json()
    assert identity["identity_id"]
    assert "BEGIN PUBLIC KEY" in identity["ecdsa_public_key"]
    assert "BEGIN PUBLIC KEY" in identity["rsa_public_key"]
    assert len(identity["ecdsa_fingerprint"].replace(":", "")) == 64
    assert len(identity["rsa_fingerprint"].replace(":", "")) == 64
    assert "private" not in response.text.lower()


def test_send_and_receive_use_crypto_pipeline_and_embed_payload():
    sender = _generate_identity()
    receiver = _generate_identity()
    cover_png = _png_bytes()

    sent = client.post(
        "/send",
        data={
            "sender_identity_id": sender["identity_id"],
            "receiver_rsa_public_key": receiver["rsa_public_key"],
            "message": "backend pipeline 🔐",
        },
        files={"cover_image": ("cover.png", cover_png, "image/png")},
    )
    assert sent.status_code == 200
    assert sent.headers["content-type"].startswith("image/png")
    token = sent.headers["x-romora-session-token"]
    stego_png = sent.content

    received = client.post(
        "/receive",
        data={
            "sender_ecdsa_public_key": sender["ecdsa_public_key"],
            "session_token": token,
        },
        files={"stego_image": ("stego.png", stego_png, "image/png")},
    )
    assert received.status_code == 200
    assert received.json() == {
        "ok": True,
        "signature_verified": True,
        "plaintext": "backend pipeline 🔐",
        "error": None,
    }


def test_tampered_image_is_rejected_without_plaintext():
    sender = _generate_identity()
    receiver = _generate_identity()
    sent = client.post(
        "/send",
        data={
            "sender_identity_id": sender["identity_id"],
            "receiver_rsa_public_key": receiver["rsa_public_key"],
            "message": "do not reveal if tampered",
        },
        files={"cover_image": ("cover.png", _png_bytes(), "image/png")},
    )
    assert sent.status_code == 200

    image = Image.open(BytesIO(sent.content)).convert("RGB")
    red, green, blue = image.getpixel((24, 0))
    image.putpixel((24, 0), (red ^ 1, green, blue))
    tampered_buffer = BytesIO()
    image.save(tampered_buffer, format="PNG")

    received = client.post(
        "/receive",
        data={
            "sender_ecdsa_public_key": sender["ecdsa_public_key"],
            "session_token": sent.headers["x-romora-session-token"],
        },
        files={"stego_image": ("tampered.png", tampered_buffer.getvalue(), "image/png")},
    )
    assert received.status_code == 400
    detail = received.json()["detail"]
    assert detail["signature_verified"] is False
    assert detail["plaintext"] is None


def test_send_rejects_missing_or_invalid_inputs():
    sender = _generate_identity()
    response = client.post(
        "/send",
        data={
            "sender_identity_id": sender["identity_id"],
            "receiver_rsa_public_key": "not a PEM key",
            "message": "message",
        },
        files={"cover_image": ("cover.png", _png_bytes(), "image/png")},
    )
    assert response.status_code == 422

    too_long = "🔐" * 48
    response = client.post(
        "/send",
        data={
            "sender_identity_id": sender["identity_id"],
            "receiver_rsa_public_key": sender["rsa_public_key"],
            "message": too_long,
        },
        files={"cover_image": ("cover.png", _png_bytes(), "image/png")},
    )
    assert response.status_code == 422
    assert "190-byte" in response.json()["detail"]


def test_authenticated_handshake_endpoints_reject_bad_signature():
    identity = _generate_identity()
    started = client.post(
        "/handshake/init", data={"identity_id": identity["identity_id"]}
    )
    assert started.status_code == 200

    _, peer_ecdh_public = generate_ecdh_keypair()
    peer_identity_private, peer_identity_public = generate_ecdsa_keypair()
    peer_public_pem = serialize_ecdh_public_key(peer_ecdh_public).decode("ascii")
    signature = sign(peer_identity_private, peer_public_pem.encode("ascii"))
    completed = client.post(
        "/handshake/complete",
        json={
            "handshake_id": started.json()["handshake_id"],
            "peer_ecdh_public_key": peer_public_pem,
            "peer_signature": base64.b64encode(signature).decode("ascii"),
            "peer_identity_public_key": serialize_ecdsa_public_key(
                peer_identity_public
            ).decode("ascii"),
        },
    )
    assert completed.status_code == 200
    assert completed.json()["session_handle"]

    another_started = client.post(
        "/handshake/init", data={"identity_id": identity["identity_id"]}
    )
    bad = client.post(
        "/handshake/complete",
        json={
            "handshake_id": another_started.json()["handshake_id"],
            "peer_ecdh_public_key": peer_public_pem,
            "peer_signature": base64.b64encode(b"invalid").decode("ascii"),
            "peer_identity_public_key": identity["ecdsa_public_key"],
        },
    )
    assert bad.status_code == 401
