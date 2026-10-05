# Guardrails: Romora Project Specification

This file is the source of truth for **what to build, how to build it, and what must never happen**. Anyone writing code for Romora (team members or AI assistants) must follow it. If something here conflicts with your idea, raise it with the team. Don't silently deviate.

Course: Cryptography and Network Security (CE305/CS305), ACNS-DC 2026-27. Team: Romora.

---

## 1. Project in one paragraph

Romora is a web application that lets a **sender** hide a secret text message inside an ordinary-looking image so that only an intended **receiver** can recover it, and can verify who sent it. The pipeline is:

> ECDH key exchange → ECDSA authentication → RSA encryption → LSB steganography (send)
> LSB extraction → RSA decryption → ECDSA verification (receive)

It delivers four properties together:

| Property | Provided by |
|---|---|
| Confidentiality | RSA-OAEP encryption of the message |
| Authenticated key exchange (no MITM) | ECDSA-signed ECDH public keys |
| Authenticity and integrity of the message | ECDSA signature over the payload |
| Covertness | LSB steganography in a lossless image |

## 2. Scope

### In scope (must build)

1. ECC-DHE key exchange (ECDH over P-256).
2. ECDSA key generation, signing and verification (P-256, SHA-256).
3. RSA-2048 key generation, OAEP encryption and decryption.
4. LSB embedding and extraction in PNG images.
5. A backend API that exposes all of the above.
6. A frontend with send and receive screens.
7. Automated tests, including a full round trip.
8. A demonstration that a tampered key or image is rejected.

### Out of scope (do **not** build unless the team agrees)

- User accounts, passwords, databases of users, or email.
- Network transport between machines (the stego-image is handed over by download or upload).
- JPEG or other lossy formats.
- Advanced steganography (adaptive embedding, steganalysis resistance).
- Hybrid AES encryption (listed as a stretch goal in section 12).
- Your own cryptographic primitives. Use vetted libraries only.

## 3. Roles and ownership

| Area | Encryption side | Decryption side |
|---|---|---|
| ECC-DHE | Key generation, handshake, shared secret | Receiver-side keys, shared secret, handshake validation |
| Digital signature | ECDSA keygen, signing | ECDSA verification, reject tampered or substituted keys |
| RSA | RSA keygen, OAEP encryption | OAEP decryption, invalid-ciphertext handling |
| Steganography | LSB embed, header, capacity check | LSB extract, header parse, rebuild ciphertext |
| Backend | One owner: API, module integration, validation, key and session storage | |
| Frontend | One owner: send and receive UI, verification status, previews | |

Names are tracked in `README.md`. **Each encryption module has a decryption counterpart, and each pair owns its interface contract.**

## 4. Technology (defaults)

| Layer | Choice |
|---|---|
| Language | Python 3.11+ |
| Crypto | `cryptography` library (no hand-rolled crypto) |
| Images | Pillow and NumPy |
| Backend | FastAPI (or Flask) |
| Frontend | React or plain HTML/JS, calling the backend over HTTP/JSON |
| Tests | `pytest` |

Changing these needs agreement from the whole team.

## 5. Architecture

```
romora/
├── crypto/
│   ├── ecdh.py        # keygen, derive_shared_secret
│   ├── ecdsa.py       # keygen, sign, verify
│   ├── rsa_enc.py     # keygen, encrypt (OAEP)
│   └── rsa_dec.py     # decrypt (OAEP)
├── stego/
│   ├── embed.py       # embed(cover_png, payload) -> stego_png
│   └── extract.py     # extract(stego_png) -> payload
├── core/
│   ├── payload.py     # build_payload / parse_payload (format in section 7)
│   ├── send.py        # full send pipeline
│   └── receive.py     # full receive pipeline
├── backend/app.py     # API layer only, no crypto logic
├── frontend/
├── tests/
├── README.md
└── Guardrails.md
```

**Layering rule:** `frontend → backend → core → crypto / stego`. Each layer calls only the layer below it. `backend/` must never contain cryptographic code, and `crypto/` must never import `backend/`.

## 6. Protocol (what happens, in order)

Roles: **A** = sender, **B** = receiver. Every party holds a long-term **ECDSA identity key pair** and an **RSA key pair**.

### 6.1 Setup (once per party)

1. Generate an ECDSA P-256 identity key pair.
2. Generate an RSA-2048 key pair.
3. Publish the **public** keys (ECDSA public, RSA public). In the demo, public keys are exchanged through the backend. Pin or display fingerprints (SHA-256 of the public key) so users can compare them out of band.

### 6.2 Authenticated ECDH handshake

1. A and B each generate a fresh ephemeral ECDH P-256 key pair.
2. Each side **signs its ephemeral ECDH public key with its ECDSA identity key** and sends `(ecdh_pub, signature, ecdsa_identity_pub)`.
3. Each side **verifies the peer's signature first**. If verification fails, **abort** and do not derive anything.
4. Both compute the ECDH shared secret, then derive a `session_key` with HKDF-SHA256 (info = `"romora-v1-session"`). The raw shared secret must never be used directly.

### 6.3 Send (A → B)

1. Encode the message as UTF-8 and check that its length is within the RSA-OAEP limit (section 8).
2. Encrypt with **B's RSA public key** using RSA-OAEP (SHA-256) to get `rsa_ciphertext`.
3. Compute `sig = ECDSA_sign(A_identity_priv, session_id || rsa_ciphertext)`, where `session_id` is derived from the session key (HKDF, info = `"romora-v1-sid"`).
4. Build the payload (section 7) as `header | rsa_ciphertext | sig`.
5. Convert to bits and embed in the LSBs of the cover PNG. Return the **stego-image as PNG**.

### 6.4 Receive (B)

1. Extract the LSB bits from the stego-image and parse the header. Validate the magic, version and length before using anything.
2. Split off `rsa_ciphertext` and `sig`.
3. **Verify the signature with A's ECDSA public key before decrypting.** If it is invalid, reject. Do not show any plaintext.
4. Decrypt with B's RSA private key (OAEP).
5. Show the plaintext and a clear "signature verified" status.

## 7. Payload format (contract between the encryption and decryption teams)

All integers are big-endian. Bytes are laid out in this order:

| Field | Size | Notes |
|---|---|---|
| `magic` | 4 B | ASCII `RMRA` |
| `version` | 1 B | `0x01` |
| `ct_len` | 2 B | length of `rsa_ciphertext` (256 for RSA-2048) |
| `sig_len` | 2 B | length of the signature (64 for raw P-256 `r‖s`) |
| `rsa_ciphertext` | `ct_len` B | |
| `signature` | `sig_len` B | |

Rules:
- This format is **frozen after the first integration**. Any change needs a version bump and the agreement of both teams.
- `payload.py` is the only place that builds or parses it.
- Parsing must reject bad magic, an unknown version, lengths that don't match, or truncated data. It must never read past the buffer.

## 8. Technical parameters (fixed)

| Item | Value |
|---|---|
| ECDH curve | P-256 (SECP256R1) |
| ECDSA | P-256 with SHA-256, raw 64-byte `r‖s` signature |
| RSA | 2048-bit, e = 65537, OAEP with MGF1-SHA256, label empty |
| KDF | HKDF-SHA256 |
| Hash for fingerprints | SHA-256 |
| Cover image format | PNG, RGB or RGBA, 8 bits per channel |
| LSB depth | 1 bit per colour channel (R, G, B only, skip alpha) |
| Max message length | RSA-2048 OAEP-SHA256 allows **190 bytes**. Reject longer input with a clear error |
| Stego capacity | `(width × height × 3) / 8` bytes, minus header. Embedding must **fail with an error** if the payload doesn't fit |

The payload is always 329 bytes (header 9 + ciphertext 256 + signature 64), which is 2,632 bits. A cover image of roughly 30×30 px is the bare minimum at 1 bit per channel. Recommend at least 256×256 px.

## 9. API contract (backend)

JSON over HTTP. Binary data is base64. All endpoints return `{ "ok": bool, "error": string|null, ... }`.

| Endpoint | Purpose |
|---|---|
| `POST /keys/generate` | Create identity (ECDSA) and RSA key pairs. Return public keys and fingerprints |
| `POST /handshake/init` | Return the signed ephemeral ECDH public key |
| `POST /handshake/complete` | Verify the peer's signed key and derive the session |
| `POST /send` | Input: message, cover image, session, receiver RSA public key. Output: stego PNG |
| `POST /receive` | Input: stego PNG, session, sender ECDSA public key. Output: plaintext and `signature_verified` |

Errors must use specific, non-leaky messages (for example `"signature invalid"`, `"image too small"`, `"payload corrupted"`). They must not expose stack traces or key material.

## 10. Frontend requirements

1. **Key setup screen:** generate keys, show fingerprints, copy or download public keys.
2. **Send screen:** message box (with a live byte counter against the 190-byte limit), cover image upload, peer's RSA public key, and a "Create stego-image" button that downloads a PNG.
3. **Receive screen:** stego-image upload, sender's public key, and a "Reveal message" button.
4. **Verification status:** a clear visible state for "signature verified" and "signature FAILED". On failure, show **no plaintext**.
5. **Cover vs stego preview:** show the two images side by side so the invisibility is visible.
6. Handle errors from the API gracefully (too-large message, image too small, invalid file).

## 11. Security guardrails (non-negotiable)

**Do**
- Use `cryptography` primitives and `os.urandom`/library RNGs for all randomness.
- Verify the signature **before** trusting the peer's key or decrypting.
- Use OAEP padding for RSA.
- Compare fingerprints and tags with constant-time comparison where relevant.
- Keep private keys in memory or in files that are git-ignored. Show fingerprints, not keys.
- Validate every input length and format at the module boundary.
- Save stego-images as **PNG only**.

**Do not**
- Never implement your own RSA, ECC, hashing or padding.
- Never use textbook RSA (no padding), PKCS#1 v1.5 encryption, ECB, MD5 or SHA-1.
- Never use a raw ECDH output as a key. Always run it through HKDF.
- Never reuse an ephemeral ECDH key across sessions.
- Never log plaintext, private keys or shared secrets.
- Never commit private keys, `.env` files or sample secrets to the repository.
- Never return a decrypted message when signature verification failed.
- Never store or serve the stego-image as JPEG, because LSB data is destroyed.
- Never hard-code keys.
- Never skip a failing test to make the demo pass.

## 12. Stretch goals (only after everything in section 2 passes)

- Hybrid mode: derive an AES-256-GCM key from the ECDH session key to encrypt long messages, and RSA-wrap or skip as appropriate.
- Key-seeded pseudo-random pixel selection for embedding.
- Image capacity indicator in the UI.
- Show an LSB-difference visualization of cover vs stego.

## 13. Testing requirements

Each module needs unit tests. The integration suite must include:

| Test | Expected |
|---|---|
| Round trip | message → stego → extract → same message, signature verified |
| Tampered stego-image (flip LSBs) | Rejected (bad signature or parse error) |
| Substituted ECDH public key (MITM simulation) | Handshake aborts |
| Wrong receiver RSA key | Decryption fails with an error, no plaintext |
| Message of exactly 190 bytes | Works |
| Message of 191 bytes | Clear error |
| Image too small | Clear error, no crash |
| JPEG upload | Rejected |
| Bad magic, bad version or truncated payload | Parse error, no crash |
| Unicode and empty-ish messages | Handled correctly |

Also check **imperceptibility**: the maximum per-channel difference between the cover and stego images must be ≤ 1, and PSNR should be reported.

## 14. Definition of done

The project is done when all of these are true:

- [ ] Every item in section 2 "In scope" is implemented.
- [ ] All tests in section 13 pass in CI or locally with one command (`pytest`).
- [ ] The demo works end to end in the UI: generate keys, handshake, send, download PNG, receive, see "verified".
- [ ] The MITM and tampering demos show clear rejection.
- [ ] No private keys or secrets are committed.
- [ ] `README.md` has working setup and run instructions.
- [ ] Code is documented (docstrings on every public function).
- [ ] The report's problem, approach and references match what was built.

## 15. Working agreements

- One branch per feature, and pull requests need one reviewer from the counterpart team (for example Embed ↔ Extract).
- Agree on interfaces first: write the function signatures and stub them before implementing.
- Integration happens early and often, not at the end.
- If you find a design problem (for example a limitation in this document), write it down and tell the team. Don't work around it quietly.
