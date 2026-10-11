"""HTTP API for Romora's existing crypto and steganography pipelines."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from collections import OrderedDict
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec, rsa
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel, Field

from core.receive import receive_message
from core.send import send_message
from crypto import ecdh, ecdsa, rsa_enc

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
MAX_IDENTITIES = 256
MAX_HANDSHAKES = 256
MAX_IMAGE_SESSIONS = 1024


@dataclass
class Identity:
    ecdsa_private: ec.EllipticCurvePrivateKey
    ecdsa_public: ec.EllipticCurvePublicKey
    rsa_private: rsa.RSAPrivateKey
    rsa_public: rsa.RSAPublicKey


@dataclass
class PendingHandshake:
    identity_id: str
    private_key: ec.EllipticCurvePrivateKey
    public_key_bytes: bytes


@dataclass
class ImageSession:
    session_id: bytes
    sender_public_key: ec.EllipticCurvePublicKey
    receiver_private_key: rsa.RSAPrivateKey


app = FastAPI(title="Romora Security API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
    expose_headers=["X-Romora-Session-Token"],
)

# Demo state is intentionally process-local; private keys are never returned.
IDENTITIES: OrderedDict[str, Identity] = OrderedDict()
RSA_IDENTITIES: dict[str, str] = {}
PENDING_HANDSHAKES: OrderedDict[str, PendingHandshake] = OrderedDict()
COMPLETED_HANDSHAKES: OrderedDict[str, bytes] = OrderedDict()
IMAGE_SESSIONS: OrderedDict[str, ImageSession] = OrderedDict()
IMAGE_HASH_TO_TOKEN: OrderedDict[str, str] = OrderedDict()


class HandshakeCompleteRequest(BaseModel):
    handshake_id: str = Field(min_length=20, max_length=100)
    peer_ecdh_public_key: str = Field(min_length=1, max_length=4096)
    peer_signature: str = Field(min_length=1, max_length=256)
    peer_identity_public_key: str = Field(min_length=1, max_length=4096)


def _require_identity(identity_id: str) -> Identity:
    identity = IDENTITIES.get(identity_id)
    if identity is None:
        raise HTTPException(status_code=404, detail="Identity was not found; generate keys again.")
    return identity


def _trim_oldest(store: OrderedDict, max_items: int) -> None:
    while len(store) > max_items:
        store.popitem(last=False)


def _fingerprint_text(fingerprint: str) -> str:
    return ":".join(fingerprint[index : index + 2] for index in range(0, len(fingerprint), 2)).upper()


def _image_fingerprint(image_bytes: bytes) -> str:
    return hashlib.sha256(image_bytes).hexdigest()


def _parse_rsa_public_key(key_pem: str) -> rsa.RSAPublicKey:
    try:
        return rsa_enc.deserialize_public_key(key_pem.encode("ascii"))
    except (UnicodeEncodeError, TypeError, ValueError):
        raise HTTPException(status_code=422, detail="Receiver RSA public key is invalid.") from None


def _parse_ecdsa_public_key(key_pem: str) -> ec.EllipticCurvePublicKey:
    try:
        public_key = ecdsa.deserialize_public_key(key_pem.encode("ascii"))
        if public_key.curve.name != "secp256r1":
            raise ValueError("Expected a P-256 public key.")
        return public_key
    except (UnicodeEncodeError, TypeError, ValueError):
        raise HTTPException(status_code=422, detail="Sender ECDSA public key is invalid.") from None


async def _read_png(file: UploadFile, label: str) -> bytes:
    if file.content_type not in ("image/png", "application/octet-stream"):
        raise HTTPException(status_code=422, detail=f"{label} must be a PNG image.")
    contents = await file.read(MAX_UPLOAD_BYTES + 1)
    if not contents:
        raise HTTPException(status_code=422, detail=f"{label} is empty.")
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="PNG upload exceeds the 10 MiB limit.")
    return contents


def _authenticated_session(
    sender: Identity, receiver: Identity
) -> tuple[bytes, bytes]:
    """Run a fresh, mutually authenticated in-process ECDH exchange."""
    sender_ephemeral_private, sender_ephemeral_public = ecdh.generate_keypair()
    receiver_ephemeral_private, receiver_ephemeral_public = ecdh.generate_keypair()
    sender_ephemeral_bytes = ecdh.serialize_public_key(sender_ephemeral_public)
    receiver_ephemeral_bytes = ecdh.serialize_public_key(receiver_ephemeral_public)
    sender_signature = ecdsa.sign(sender.ecdsa_private, sender_ephemeral_bytes)
    receiver_signature = ecdsa.sign(receiver.ecdsa_private, receiver_ephemeral_bytes)

    if not ecdsa.verify(sender.ecdsa_public, sender_ephemeral_bytes, sender_signature):
        raise ValueError("Sender handshake signature verification failed.")
    if not ecdsa.verify(receiver.ecdsa_public, receiver_ephemeral_bytes, receiver_signature):
        raise ValueError("Receiver handshake signature verification failed.")

    sender_session_key, sender_session_id = ecdh.derive_session(
        sender_ephemeral_private, receiver_ephemeral_public
    )
    receiver_session_key, receiver_session_id = ecdh.derive_session(
        receiver_ephemeral_private, sender_ephemeral_public
    )
    if not hmac.compare_digest(sender_session_key, receiver_session_key) or not hmac.compare_digest(
        sender_session_id, receiver_session_id
    ):
        raise ValueError("ECDH session derivation failed.")
    return sender_session_key, sender_session_id


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/keys/generate")
def generate_keys() -> dict[str, str]:
    ecdsa_private, ecdsa_public = ecdsa.generate_keypair()
    rsa_private, rsa_public = rsa_enc.generate_keypair()
    identity_id = secrets.token_urlsafe(32)
    identity = Identity(ecdsa_private, ecdsa_public, rsa_private, rsa_public)

    IDENTITIES[identity_id] = identity
    IDENTITIES.move_to_end(identity_id)
    RSA_IDENTITIES[rsa_enc.public_key_fingerprint(rsa_public)] = identity_id
    _trim_oldest(IDENTITIES, MAX_IDENTITIES)
    active_ids = set(IDENTITIES)
    for fingerprint, stored_id in list(RSA_IDENTITIES.items()):
        if stored_id not in active_ids:
            del RSA_IDENTITIES[fingerprint]

    ecdsa_fingerprint = ecdsa.public_key_fingerprint(ecdsa_public)
    rsa_fingerprint = rsa_enc.public_key_fingerprint(rsa_public)
    return {
        "identity_id": identity_id,
        "ecdsa_public_key": ecdsa.serialize_public_key(ecdsa_public).decode("ascii"),
        "rsa_public_key": rsa_enc.serialize_public_key(rsa_public).decode("ascii"),
        "ecdsa_fingerprint": _fingerprint_text(ecdsa_fingerprint),
        "rsa_fingerprint": _fingerprint_text(rsa_fingerprint),
    }


@app.post("/handshake/init")
def handshake_init(identity_id: str = Form(...)) -> dict[str, str]:
    identity = _require_identity(identity_id)
    private_key, public_key = ecdh.generate_keypair()
    public_bytes = ecdh.serialize_public_key(public_key)
    signature = ecdsa.sign(identity.ecdsa_private, public_bytes)
    handshake_id = secrets.token_urlsafe(32)
    PENDING_HANDSHAKES[handshake_id] = PendingHandshake(
        identity_id=identity_id,
        private_key=private_key,
        public_key_bytes=public_bytes,
    )
    PENDING_HANDSHAKES.move_to_end(handshake_id)
    _trim_oldest(PENDING_HANDSHAKES, MAX_HANDSHAKES)
    return {
        "handshake_id": handshake_id,
        "ecdh_public_key": public_bytes.decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
        "identity_public_key": ecdsa.serialize_public_key(identity.ecdsa_public).decode("ascii"),
    }


@app.post("/handshake/complete")
def handshake_complete(request: HandshakeCompleteRequest) -> dict[str, str]:
    pending = PENDING_HANDSHAKES.pop(request.handshake_id, None)
    if pending is None:
        raise HTTPException(status_code=404, detail="Handshake was not found or has expired.")
    identity = _require_identity(pending.identity_id)
    try:
        peer_signature = base64.b64decode(request.peer_signature, validate=True)
        peer_public = ecdh.deserialize_public_key(request.peer_ecdh_public_key.encode("ascii"))
        peer_identity_public = _parse_ecdsa_public_key(request.peer_identity_public_key)
    except (ValueError, TypeError, UnicodeEncodeError):
        raise HTTPException(status_code=422, detail="Peer handshake data is invalid.") from None
    if not ecdsa.verify(peer_identity_public, request.peer_ecdh_public_key.encode("ascii"), peer_signature):
        raise HTTPException(status_code=401, detail="Peer handshake signature verification failed.")
    session_key, session_id = ecdh.derive_session(pending.private_key, peer_public)
    del session_key
    session_handle = secrets.token_urlsafe(32)
    COMPLETED_HANDSHAKES[session_handle] = session_id
    COMPLETED_HANDSHAKES.move_to_end(session_handle)
    _trim_oldest(COMPLETED_HANDSHAKES, MAX_HANDSHAKES)
    return {
        "session_handle": session_handle,
        "identity_fingerprint": ecdsa.public_key_fingerprint(identity.ecdsa_public),
    }


@app.post("/send")
async def send(
    sender_identity_id: str = Form(...),
    receiver_rsa_public_key: str = Form(...),
    message: str = Form(...),
    cover_image: UploadFile = File(...),
) -> Response:
    if not message:
        raise HTTPException(status_code=422, detail="Message must not be empty.")
    if len(message.encode("utf-8")) > rsa_enc.MAX_MESSAGE_BYTES:
        raise HTTPException(
            status_code=422,
            detail=f"Message exceeds the {rsa_enc.MAX_MESSAGE_BYTES}-byte UTF-8 limit.",
        )

    sender = _require_identity(sender_identity_id)
    receiver_public = _parse_rsa_public_key(receiver_rsa_public_key)
    receiver_id = RSA_IDENTITIES.get(rsa_enc.public_key_fingerprint(receiver_public))
    if receiver_id is None:
        raise HTTPException(
            status_code=422,
            detail="Receiver key was not generated by this backend deployment.",
        )
    receiver = IDENTITIES[receiver_id]
    cover_png = await _read_png(cover_image, "Cover image")
    try:
        _, session_id = _authenticated_session(sender, receiver)
        stego_png = send_message(
            message=message,
            cover_png=cover_png,
            session_id=session_id,
            sender_ecdsa_priv=sender.ecdsa_private,
            receiver_rsa_pub=receiver_public,
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from None

    token = secrets.token_urlsafe(32)
    image_session = ImageSession(session_id, sender.ecdsa_public, receiver.rsa_private)
    IMAGE_SESSIONS[token] = image_session
    IMAGE_SESSIONS.move_to_end(token)
    image_hash = _image_fingerprint(stego_png)
    IMAGE_HASH_TO_TOKEN[image_hash] = token
    IMAGE_HASH_TO_TOKEN.move_to_end(image_hash)
    _trim_oldest(IMAGE_SESSIONS, MAX_IMAGE_SESSIONS)
    _trim_oldest(IMAGE_HASH_TO_TOKEN, MAX_IMAGE_SESSIONS)
    return Response(
        content=stego_png,
        media_type="image/png",
        headers={"X-Romora-Session-Token": token},
    )


@app.post("/receive")
async def receive(
    sender_ecdsa_public_key: str = Form(...),
    stego_image: UploadFile = File(...),
    session_token: str = Form(""),
) -> dict[str, object]:
    stego_png = await _read_png(stego_image, "Stego image")
    exact_image_token = IMAGE_HASH_TO_TOKEN.get(_image_fingerprint(stego_png), "")
    token = exact_image_token or session_token
    image_session = IMAGE_SESSIONS.get(token)
    if image_session is None:
        raise HTTPException(
            status_code=404,
            detail="Image session was not found; send and receive on the same backend deployment.",
        )
    sender_public = _parse_ecdsa_public_key(sender_ecdsa_public_key)
    expected_fingerprint = ecdsa.public_key_fingerprint(image_session.sender_public_key)
    if not hmac.compare_digest(
        ecdsa.public_key_fingerprint(sender_public), expected_fingerprint
    ):
        raise HTTPException(status_code=401, detail="Sender public key does not match this image.")

    result = receive_message(
        stego_png=stego_png,
        session_id=image_session.session_id,
        sender_ecdsa_pub=sender_public,
        receiver_rsa_priv=image_session.receiver_private_key,
    )
    response: dict[str, object] = {
        "ok": result.ok,
        "signature_verified": result.signature_verified,
        "plaintext": result.plaintext if result.signature_verified else None,
        "error": result.error,
    }
    if not result.ok:
        raise HTTPException(status_code=400, detail=response)
    return response
