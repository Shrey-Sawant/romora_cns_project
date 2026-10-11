# Romora: Engineering Suggestions & Implementation Notes

This document provides architectural guidance, implementation blueprints, and recommendations for the remaining development phases of the **Romora** project.

---

## 1. Suggestions for the Backend Developer (Manasvi More)

The core cryptographic and steganographic pipelines (`core/send.py`, `core/receive.py`, `crypto/`, `stego/`) are ready and tested. The backend layer in `backend/app.py` should serve solely as an HTTP interface over these core functions, containing no direct crypto math.

### 1.1. Recommended FastAPI Skeleton (`backend/app.py`)
```python
import base64
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from core.receive import receive_message
from core.send import send_message
from crypto import ecdh, ecdsa, rsa_enc

app = FastAPI(title="Romora Security API", version="1.0.0")

# Enable CORS for the Vite development server
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory session store (mapping session_id_hex -> session_data)
SESSION_STORE = {}
```

### 1.2. Key Architectural Guidelines
1. **Never Log Sensitive Material:** Do not log private keys, raw shared secrets, or plaintext messages in console logs or error messages.
2. **Handle Binary Data Appropriately:**
   * Return the stego-image directly as binary PNG bytes with media type `image/png` (`Response(content=stego_bytes, media_type="image/png")`) so the browser can download or preview it directly.
   * Public keys can be exchanged as standard PEM strings.
3. **Session Store:**
   * Map `session_id.hex()` to ephemeral handshake state.
   * For the demo, an in-memory dictionary is recommended (Guardrails out-of-scope rules forbid database setup).
4. **Error Handling Without Information Leakage:**
   * Catch `ValueError` or `SecurityVerificationError` from `core/receive.py` and return `{ "ok": false, "error": str(e) }` with HTTP 400/422 status, without returning stack traces.

---

## 2. Suggestions for the Frontend Developer (Vivek Dagale)

The UI mockup in `frontend/src/main.jsx` is visually structured. To make it a working application connected to the backend, apply the following adjustments:

### 2.1. UTF-8 Byte Counter on Send Screen
In JavaScript, `"🔐".length === 2`, but `new TextEncoder().encode("🔐").length === 4`. Since RSA-OAEP operates on raw bytes (strict limit: **190 bytes**):
```javascript
const getByteLength = (text) => new TextEncoder().encode(text).length;
const byteCount = getByteLength(message);
const isOverLimit = byteCount > 190;
```
Disable the **"Create Stego-Image"** button if `byteCount === 0 || isOverLimit`.

### 2.2. Handling Stego PNG Downloads
When receiving binary image data from `POST /send`:
```javascript
const response = await fetch('http://localhost:8000/send', {
  method: 'POST',
  body: formData,
});
const blob = await response.blob();
const downloadUrl = URL.createObjectURL(blob);

// Trigger file download
const a = document.createElement('a');
a.href = downloadUrl;
a.download = 'romora_stego.png';
a.click();
```

### 2.3. Fail-Closed Verification UI
On the Receive screen:
* Check `data.signature_verified`.
* **If `true`:** Navigate to the **"Verification Successful"** screen and render `data.plaintext`.
* **If `false`:** Navigate to the **"Verification Failed"** screen. Ensure that the decrypted text element is completely unmounted or absent from the DOM (never just hidden with CSS).

### 2.4. Demonstration Features for the Live Presentation
* **Live Tamper Demonstration:** Add a demo button on the Receive screen: *"Simulate Image Tampering (Flip 1 bit)"*. This will flip a single pixel bit in the uploaded image before submitting, proving to the evaluators that Romora detects tampering and withholds the plaintext.
* **Side-by-Side Image Difference:** Show the original cover image alongside the stego image. Highlight that the human eye cannot detect the difference, and display the calculated PSNR score ($>50\text{ dB}$).

---

## 3. Suggestions for the Encryption Team (Gangesh, Shrey, Jay, Pranav)

1. **Merge Git Feature Branches:**
   * Merge `origin/feat/pranav-lsb-embedding` into `main` so that all teammates share the identical commit history for `stego/embed.py`.
2. **Keep `core/payload.py` Frozen:**
   * The binary wire layout (`RMRA` magic, 1-byte version, 256-byte ciphertext, 64-byte signature = 329 bytes total) is the frozen contract between sender and receiver. Do not alter the header structure without incrementing the version number.
3. **Capacity Check:**
   * When accepting custom user images, verify dimensions beforehand:
     $$\text{Capacity in bytes} = \frac{\text{width} \times \text{height} \times 3}{8}$$
     Ensure capacity $\ge 329\text{ bytes}$ ($\ge 878\text{ pixels}$).

### 3.4. Integrate Pranav's Sender-Side LSB Embedder

- **Pranav Gadge:** The sender-side LSB embedding module is implemented in `stego/embed.py`. It accepts a cover image and an already-serialized payload, embeds the payload bits into the RGB channel LSBs, validates image capacity, preserves RGBA transparency, and returns the stego-image as PNG bytes.
- **Manasvi More (Backend):** Integrate `stego.embed.embed()` into the send pipeline after encryption and payload serialization. Return the generated PNG bytes from the API using `image/png`.
- **Vivek Dagale (Frontend):** Connect the image-upload and send interface to the backend API. Allow users to select a cover image, initiate the send operation, preview the resulting stego-image, and download it as a PNG.
- **Ayushri Dalvi (Receiver-side Steganography):** Ensure the extraction module uses the same payload format, bit ordering, and RGB traversal order so the original serialized payload can be reconstructed correctly.

The embedder does not perform encryption or add a second payload header. The backend must pass it the complete serialized payload defined by `core/payload.py`.

---

## 4. Suggestions for the Final ACNS-DC Report & Presentation

1. **Threat Model & Security Proof:**
   * **Confidentiality:** Guaranteed by RSA-2048 OAEP. Even if steganalysis reveals hidden data, the attacker only obtains ciphertext.
   * **Integrity & Authenticity:** Guaranteed by ECDSA. Any modification of carrier pixels alters the ciphertext or signature, causing ECDSA verification to fail.
   * **MITM Protection:** Guaranteed by signing ephemeral ECDH keys with long-term ECDSA identity keys during the handshake.
   * **Covertness:** Lossless LSB embedding alters at most 1 bit per RGB channel, maintaining PSNR $> 50\text{ dB}$.
2. **Performance Metrics to Highlight:**
   * Handshake latency: $< 5\text{ ms}$.
   * Embedding latency for $256 \times 256$ PNG: $< 15\text{ ms}$.
   * Decryption & verification latency: $< 10\text{ ms}$.
