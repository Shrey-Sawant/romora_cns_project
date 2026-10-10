# Romora: Authenticated Encrypted Image Steganography

**Applied Cryptography and Network Security Design Challenge (ACNS-DC) 2026-27**
Cryptography and Network Security (CE305/CS305), Bharatiya Vidya Bhavan's Sardar Patel Institute of Technology, Mumbai

Team: **Romora**

---

## Overview

Sensitive messages face two linked risks:

1. **Visible ciphertext.** Ordinary encryption hides the content of a message but not the fact that a secret exchange is happening. That invites interception, traffic analysis and targeted attacks.
2. **Unauthenticated key exchange.** Public keys exchanged over an insecure channel can be swapped by a man-in-the-middle (MITM) attacker.

Romora combines four mechanisms into one pipeline:

| Goal | Mechanism |
|---|---|
| Shared session context | **ECDH** (Elliptic-Curve Diffie-Hellman) |
| Authentication and MITM protection | **ECDSA** digital signatures |
| Message confidentiality | **RSA** encryption with the recipient's public key |
| Covertness | **LSB image steganography** |

The result is a normal-looking image that carries an encrypted, authenticated message.

## How It Works

```
SENDER                                                        RECEIVER
  |  1. ECDH handshake (each side signs its public key, ECDSA)   |
  |<------------------------------------------------------------>|
  |  2. Verify peer's signature, derive shared secret            |
  |                                                              |
  |  3. Encrypt message with receiver's RSA public key           |
  |  4. Ciphertext -> bit stream                                 |
  |  5. Embed bits in the LSBs of a cover image -> stego-image   |
  |------------------- stego-image ----------------------------->|
  |                                                              |
  |            6. Extract LSBs -> rebuild RSA ciphertext         |
  |            7. Decrypt with receiver's RSA private key        |
  |            8. Verify sender's ECDSA signature                |
  |            9. Accept the message only if verification passes |
```

## Why This Design

| Technique alone | Gap | How Romora closes it |
|---|---|---|
| RSA | Slow for large data, ciphertext is visibly "encrypted" | Ciphertext is hidden inside an image |
| LSB steganography | No encryption, so detection exposes the plaintext | The embedded payload is already RSA-encrypted |
| Classic Diffie-Hellman | MITM-vulnerable, large keys | ECDH gives smaller keys, ECDSA authenticates each public key |

## Project Structure (suggested)

```
romora/
├── crypto/
│   ├── ecdh.py          # ECDH key generation and shared-secret derivation
│   ├── ecdsa.py         # Sign and verify public keys and messages
│   ├── rsa_enc.py       # RSA keygen, encrypt (OAEP)
│   └── rsa_dec.py       # RSA decrypt
├── stego/
│   ├── embed.py         # LSB embedding
│   └── extract.py       # LSB extraction
├── backend/             # API server
├── frontend/            # Web UI
├── tests/
└── README.md
```

## Suggested Tech Stack

The report doesn't fix a stack, so these are suggestions. Change them if the team picks something else.

- **Crypto:** Python with `cryptography`
- **Imaging:** Pillow and NumPy
- **Backend:** Flask or FastAPI
- **Frontend:** React, or plain HTML/JS

## Getting Started

```bash
git clone <repo-url> && cd romora
pip install -r requirements.txt
python -m backend.app        # start the API
# open the frontend at http://localhost:3000
```

*(Update these commands once the code is in place.)*

## Work Distribution (10 members)

| Role | Size | Members |
|---|---|---|
| Encryption | 4 | Gangesh Dhangar,Shrey Sawant,Jay Patil, Pranav Gadge |
| Decryption | 4 | Nirupam Gupta, Kankshi Shah,Ayushri Dalvi, Raizel Marti |
| Backend | 1 | Manasvi More |
| Frontend | 1 | Vivek Dagale |

The assignment follows the roster order. Swap names freely.

### Encryption team (sender side)

| Member | Task |
|---|---|
| Jay Patil | ECC-DHE: key generation, handshake, shared-secret derivation |
| Shrey Sawant | Digital signature: ECDSA key generation, signing of public keys and messages |
| Gangesh Dhangar | RSA: key generation and message encryption (OAEP padding) |
| Pranav Gadge | Steganography: LSB embedding, payload header (length), bit conversion, capacity check, stego-image output |

### Decryption team (receiver side)

| Member | Task |
|---|---|
| Nirupam Gupta | ECC-DHE: receiver-side key generation, shared-secret derivation, handshake validation |
| Kankshi Shah | Digital signature: ECDSA verification, rejecting tampered or substituted keys |
| Raizel Marti | RSA: private-key decryption of the recovered ciphertext (OAEP), error handling for invalid ciphertext |
|Ayushri Dalvi | Steganography: LSB extraction, read the header, recover the bit stream, rebuild the ciphertext |

Both teams cover the same four areas: **ECC-DHE, digital signature, RSA and steganography**. Each pair works as a counterpart, and the pairs must agree on interfaces and the **payload format** early. Round-trip tests catch mismatches.

| Area | Encryption side | Decryption side |
|---|---|---|
| ECC-DHE | Jay Patil | Nirupam Gupta |
| Digital signature (ECDSA) | Shrey Sawant | Kankshi Shah |
| RSA | Gangesh Dhangar | Raizel Marti |
| Steganography (LSB) | Pranav Gadge | Ayushri Dalvi |

### Backend ( Manasvi More )

- API endpoints: key exchange, encrypt-and-embed, extract-and-decrypt
- Integrate the encryption and decryption modules
- Handle image upload and download, validation, and error responses
- Key storage and session handling

### Frontend ( Vivek Dagale)

- Screens: key setup, send (message plus cover image), receive (stego-image)
- Show verification status (signature valid or invalid) and the decrypted message
- Preview the cover image beside the stego-image
- Connect to the backend API

### Shared

- Write the integration tests together: encrypt, embed, extract, decrypt must return the original message.
- Prepare the demo and the final report.

## Limitations and Notes

- Plain RSA-OAEP only encrypts short messages (about 190 bytes for a 2048-bit key). Longer messages need chunking or a hybrid scheme, for example an AES key derived from the ECDH secret.
- LSB steganography is vulnerable to steganalysis and to lossy compression. Use lossless formats such as PNG and never re-save the stego-image as JPEG.
- The image's capacity limits the message size, so the embedder must check capacity first.

## References

1. R. L. Rivest, A. Shamir, and L. Adleman, "A Method for Obtaining Digital Signatures and Public-Key Cryptosystems," *Communications of the ACM*, 1978.
2. NIST SP 800-56A Rev. 3: *Recommendation for Pair-Wise Key-Establishment Schemes Using Discrete Logarithm Cryptography* (ECDH), 2018.
3. NIST FIPS 186-5: *Digital Signature Standard (DSS)* (ECDSA), 2023.
4. N. F. Johnson and S. Jajodia, "Exploring Steganography: Seeing the Unseen," *IEEE Computer*, vol. 31, no. 2, 1998.

## Team Romora

| Batch | Name | ID |
|---|---|---|
| D1 | Gangesh Dhangar | 2025301006 |
| D4 | Vivek Dagale | 2025301004 |
| D4 | Ayushri Dalvi | 2025301005 |
| D4 | Pranav Gadge | 2025301007 |
| D4 | Nirupam Gupta | 2025301009 |
| D4 | Kankshi Shah | 2025301014 |
| D4 | Raizel Marti | 2025301019 |
| D4 | Manasvi More | 2025301020 |
| D4 | Jay Patil | 2025301023 |
| D4 | Shrey Sawant | 2025301027 |
