# Romora Project: Current State & Completion Tracker

> **Applied Cryptography and Network Security Design Challenge (ACNS-DC) 2026-27**  
> Course: Cryptography and Network Security (CE305/CS305), SPIT Mumbai  
> Repository: `Shrey-Sawant/romora_cns_project`  
> Last Updated: 2026-10-11

---

## Overall Project Completion: ~65%

```
[█████████████░░░░░░░] 65% Complete
```

| Area | Progress | Status | Notes |
| :--- | :---: | :---: | :--- |
| **Decryption Sub-System (Receiver)** | **100%** | **Complete** | All modules (`ecdh`, `rsa_dec`, `extract`, `receive`) implemented & tested. |
| **Cryptography Core** | **100%** | **Complete** | ECDSA, ECDH, RSA-2048 encryption & decryption complete. |
| **Steganography Engine** | **100%** | **Complete** | LSB 1-bit/channel embedding & extraction complete. |
| **Wire Protocol & Core Pipelines** | **100%** | **Complete** | Canonical 329-byte framing, `send_message`, `receive_message` complete. |
| **Automated Testing Suite** | **95%** | **Complete** | 45 pytest tests passing (unit, security invariants, round-trip, PSNR). |
| **Backend REST API** | **10%** | **In Progress** | Specifications ready in `Guardrails.md`; FastAPI endpoints pending. |
| **Frontend Web Application** | **40%** | **In Progress** | UI mockup & layouts ready; API wiring and dynamic state pending. |

---

## Detailed Task Breakdown by Sub-System

### 1. Cryptographic Primitives (`crypto/`) — 100% Complete
- [x] **ECDSA Digital Signatures (`crypto/ecdsa.py`)** *(Shrey Sawant & Kankshi Shah)*
  - [x] Key generation on curve P-256 (`SECP256R1`).
  - [x] Canonical raw 64-byte $(r \parallel s)$ signature format.
  - [x] DER $\leftrightarrow$ raw signature conversion.
  - [x] PEM SubjectPublicKeyInfo and PKCS#8 serialization/deserialization.
  - [x] SHA-256 public key fingerprinting.
  - [x] Unit tests (`tests/test_ecdsa.py`) passing (6/6).
- [x] **ECDH Key Exchange & Session Derivation (`crypto/ecdh.py`)** *(Jay Patil & Nirupam Gupta)*
  - [x] Ephemeral P-256 keypair generation.
  - [x] Raw shared secret computation (`ec.ECDH()`).
  - [x] HKDF-SHA256 session key derivation (`info=b"romora-v1-session"`).
  - [x] HKDF-SHA256 session ID derivation (`info=b"romora-v1-sid"`).
  - [x] Handshake verification and MITM abort on invalid peer signature.
  - [x] Unit tests (`tests/test_ecdh.py`) passing (5/5).
- [x] **RSA-2048 Encryption (`crypto/rsa_enc.py`)** *(Gangesh Dhangar)*
  - [x] Keypair generation ($e=65537$, 2048-bit).
  - [x] OAEP padding with MGF1-SHA256, SHA-256 hash, empty label.
  - [x] 190-byte maximum plaintext enforcement.
  - [x] PEM serialization/deserialization & SHA-256 fingerprinting.
  - [x] Unit tests (`tests/test_rsa_enc.py`) passing (11/11).
- [x] **RSA-2048 Decryption (`crypto/rsa_dec.py`)** *(Raizel Marti)*
  - [x] Private-key decryption of 256-byte ciphertext.
  - [x] Matching OAEP padding parameters.
  - [x] Safe error handling (no stack trace or key leakage on invalid ciphertext).
  - [x] UTF-8 string decoding and validation.
  - [x] Unit tests (`tests/test_rsa_dec.py`) passing (6/6).

---

### 2. Steganography Engine (`stego/`) — 100% Complete
- [x] **LSB Embedding (`stego/embed.py`)** *(Pranav Gadge)*
  - [x] 1 bit per color channel (R, G, B), alpha channel untouched.
  - [x] MSB-first bit order, row-major pixel traversal.
  - [x] PNG format validation & image capacity check.
- [x] **LSB Extraction (`stego/extract.py`)** *(Ayushri Dalvi)*
  - [x] Row-major RGB LSB bit extraction.
  - [x] 9-byte header extraction and dynamic payload length parsing.
  - [x] Lossless PNG validation; rejection of JPEG/lossy images.
  - [x] Unit tests (`tests/test_extract.py`) passing (5/5).

---

### 3. Core Wire Format & Orchestration (`core/`) — 100% Complete
- [x] **Wire Payload Framing (`core/payload.py`)** *(Joint)*
  - [x] Magic identifier `RMRA` (4 bytes).
  - [x] Protocol version `0x01` (1 byte).
  - [x] Length headers: `ct_len` (2 bytes = 256), `sig_len` (2 bytes = 64).
  - [x] Total fixed payload size: **329 bytes**.
  - [x] Strict bounds check & truncated payload rejection.
  - [x] Unit tests (`tests/test_payload.py`) passing (5/5).
- [x] **Sender Pipeline (`core/send.py`)** *(Encryption Team)*
  - [x] Message size check $\le 190$ bytes.
  - [x] RSA-OAEP encryption $\to$ ECDSA sign $(session\_id \parallel rsa\_ciphertext)$ $\to$ pack payload $\to$ LSB embed.
- [x] **Receiver Pipeline (`core/receive.py`)** *(Decryption Team)*
  - [x] LSB extract $\to$ unpack payload $\to$ ECDSA verify $\to$ RSA decrypt.
  - [x] **Fail-closed security rule enforced**: Zero plaintext leakage if signature fails or image is tampered.
  - [x] Integration tests (`tests/test_receive.py`) passing (6/6).

---

### 4. Quality Assurance & Security Invariants (`tests/`) — 95% Complete
- [x] Total passing tests: **45 / 45**.
- [x] **MITM Attack Simulation:** Verifies handshake aborts when ephemeral key or signature is forged.
- [x] **Tampering Detection:** Verifies 1-bit pixel flip causes signature rejection and zero plaintext leak.
- [x] **Key Substitution Defense:** Verifies rejection when decrypted with wrong private key or wrong sender identity.
- [x] **Visual Imperceptibility Test (`tests/test_roundtrip.py`):**
  - Maximum per-channel pixel difference $\le 1$.
  - Peak Signal-to-Noise Ratio (PSNR) $> 50\text{ dB}$.
- [ ] End-to-end API HTTP integration tests (pending backend completion).

---

### 5. Backend REST API (`backend/`) — 10% Complete
**Assigned to:** Manasvi More  
- [ ] Setup FastAPI server in `backend/app.py`.
- [ ] Implement `POST /keys/generate` (Generate ECDSA & RSA keys, return PEM + fingerprints).
- [ ] Implement `POST /handshake/init` (Ephemeral ECDH keygen & signed public key).
- [ ] Implement `POST /handshake/complete` (Peer signature validation & session derivation).
- [ ] Implement `POST /send` (Call `core.send.send_message`, return stego PNG).
- [ ] Implement `POST /receive` (Call `core.receive.receive_message`, return plaintext & status).
- [ ] In-memory session store for ephemeral handshakes.
- [ ] CORS middleware for frontend communication (`localhost:5173`).

---

### 6. Frontend Web Application (`frontend/`) — 40% Complete
**Assigned to:** Vivek Dagale  
- [x] UI scaffolding in React + Vite (`frontend/src/main.jsx`).
- [x] Dark cyber security visual aesthetic and navigation tabs.
- [x] Static mockups for Key Setup, Send, Processing, Created, Receive, Verification screens.
- [ ] Connect Key Setup screen to `POST /keys/generate` API.
- [ ] Dynamic 190-byte UTF-8 live counter on Send screen.
- [ ] Connect Send screen to `POST /send` API and handle PNG download.
- [ ] Connect Receive screen to `POST /receive` API.
- [ ] Dynamic verification feedback (Green "Verified" badge vs. Red "Tampering Detected" screen).
- [ ] Side-by-side Cover vs. Stego comparison with PSNR display.

---

## Summary of Team Contributions

| Team Member | Sub-System | Status |
| :--- | :--- | :---: |
| **Nirupam Gupta** | ECC-DHE Receiver, Handshake Validation, Test Suite | **100% Complete** |
| **Kankshi Shah** | Digital Signature Verification, Tampering Invariants | **100% Complete** |
| **Ayushri Dalvi** | Steganography LSB Extraction, PNG Validation | **100% Complete** |
| **Raizel Marti** | RSA-OAEP Decryption, Error Isolation | **100% Complete** |
| Jay Patil | ECC-DHE Sender | Ready for integration |
| Shrey Sawant | Digital Signature Generation | Merged to main |
| Gangesh Dhangar | RSA-2048 Encryption | Merged to main |
| Pranav Gadge | Steganography LSB Embedding | Implemented on branch |
| Manasvi More | Backend API & Session Store | Next priority |
| Vivek Dagale | Frontend API Integration & Dynamic State | Next priority |
